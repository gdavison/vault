package oracle

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const SecretCredsType = "creds"

const revocationSQL = `
REVOKE CONNECT FROM {{name}};
REVOKE CREATE SESSION FROM {{name}};
DROP USER {{name}};
`

const sessionQuerySQL = `SELECT sid, serial#, username FROM v$session WHERE username = UPPER('{{name}}')`

const sessionKillSQL = `ALTER SYSTEM KILL SESSION '%d,%d' IMMEDIATE`

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

	var resp *logical.Response

	var err error

	// Get our connection
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// Disconnect the session
	disconnectStmt, err := db.Prepare(Query(sessionQuerySQL, map[string]string{
		"name": username,
	}))
	if err != nil {
		return nil, err
	}
	defer disconnectStmt.Close()
	if rows, err := disconnectStmt.Query(); err != nil {
		return nil, err
	} else {
		defer rows.Close()
		for rows.Next() {
			var sessionId, serialNumber int
			var username sql.NullString
			err = rows.Scan(&sessionId, &serialNumber, &username)
			if err != nil {
				return nil, err
			}
			killStatement := fmt.Sprintf(sessionKillSQL, sessionId, serialNumber)
			_, err = db.Exec(killStatement)
			if err != nil {
				return nil, err
			}
		}
		err = rows.Err()
		if err != nil {
			return nil, err
		}
	}

	// We can't use a transaction here, because Oracle treats DROP USER as a DDL statement, which commits immediately.
	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(revocationSQL, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		stmt, err := db.Prepare(Query(query, map[string]string{
			"name": username,
		}))
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
