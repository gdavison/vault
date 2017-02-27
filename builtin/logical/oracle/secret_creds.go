package oracle

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const SecretCredsType = "creds"

const defaultRevocationSQL = `
REVOKE CONNECT FROM {{name}};
REVOKE CREATE SESSION FROM {{name}};
DROP USER {{name}};
`

// without this statement, it doesn't close existing connections
// but this statement isn't quite correct
//select 'alter system kill session ''' || sid || ',' || serial# || ''';' from v$session where username = '{{name}}'

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
	// Get the lease information
	lease, err := b.Lease(req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	f := framework.LeaseExtend(lease.Lease, lease.LeaseMax, b.System())
	return f(req, d)
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

	var resp *logical.Response

	roleName := ""
	roleNameRaw, ok := req.Secret.InternalData["role"]
	if ok {
		roleName = roleNameRaw.(string)
	}

	var err error

	var role *roleEntry
	if roleName != "" {
		role, err = b.Role(req.Storage, roleName)
		if err != nil {
			return nil, err
		}
	}

	revocationSQL := defaultRevocationSQL

	if role != nil && role.RevocationSQL != "" {
		revocationSQL = role.RevocationSQL
	} else {
		if resp == nil {
			resp = &logical.Response{}
		}
		resp.AddWarning(fmt.Sprintf("Role %q cannot be found. Using default SQL for revoking user.", roleName))
	}
	b.logger.Trace("REVOCATION SQL", "sql", revocationSQL)

	// Get our connection
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// We can't use a transaction here, because Oracle treats DROP USER as a DDL statement, which commits immediately.
	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(revocationSQL, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		b.logger.Trace("oracle/secretCredsRevoke: preparing statement", "query", query, "name", username)
		stmt, err := db.Prepare(Query(query, map[string]string{
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

	return resp, nil
}
