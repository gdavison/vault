package oracle

import (
	//	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	//	oci8 "github.com/mattn/go-oci8"
)

const SecretCredsType = "creds"

// Do I need to
//REVOKE ALL PRIVILEGES FROM {{name}};
const defaultRevocationSQL = `
DROP USER {{name}}
`

func secretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username",
			},

			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Password",
			},
		},

		Renew:  b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRenew(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the username from the internal data
	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}
	username, ok := usernameRaw.(string)

	// Get our connection
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// Get the lease information
	lease, err := b.Lease(req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	f := framework.LeaseExtend(lease.Lease, lease.LeaseMax, b.System())
	resp, err := f(req, d)
	if err != nil {
		return nil, err
	}

	// Make sure we increase the VALID UNTIL endpoint for this user.
	if expireTime := resp.Secret.ExpirationTime(); !expireTime.IsZero() {
		expiration := expireTime.Format("2006-01-02 15:04:05-0700")

		query := fmt.Sprintf(
			"ALTER ROLE '%s' VALID UNTIL '%s';",
			username,
			expiration)
		stmt, err := db.Prepare(query)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		if _, err := stmt.Exec(); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (b *backend) secretCredsRevoke(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the username from the internal data
	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}
	username, ok := usernameRaw.(string)
	b.logger.Trace("oracle/secretCredsRevoke", "username", username)

	var revocationSQL string
	var resp *logical.Response

	roleNameRaw, ok := req.Secret.InternalData["role"]
	if ok {
		role, err := b.Role(req.Storage, roleNameRaw.(string))
		if err != nil {
			return nil, err
		}
		if role == nil {
			if resp == nil {
				resp = &logical.Response{}
			}
			resp.AddWarning(fmt.Sprintf("Role %q cannot be found. Using default revocation SQL.", roleNameRaw.(string)))
		} else {
			revocationSQL = role.RevocationSQL
		}
	}

	// Get our connection
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// Start a transaction
	b.logger.Trace("oracle/secretCredsRevoke: starting transaction")
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		b.logger.Trace("oracle/secretCredsRevoke: rolling back transaction")
		tx.Rollback()
	}()

	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(revocationSQL, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		b.logger.Trace("oracle/secretCredsRevoke: preparing statement")
		b.logger.Trace("foo", "Query", query)
		b.logger.Trace("foo", "name", username)
		stmt, err := tx.Prepare(Query(query, map[string]string{
			"name": username,
		}))
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		b.logger.Trace("oracle/secretCredsRevoke: executing statement")
		if _, err := stmt.Exec(); err != nil {
			return nil, err
		}
	}

	// Commit the transaction
	b.logger.Trace("oracle/secretCredsRevoke: committing transaction")
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return resp, nil
}
