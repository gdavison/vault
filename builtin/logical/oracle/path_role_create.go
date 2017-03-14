package oracle

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/mattn/go-oci8"
)

const oracleUsernameLength = 30
const oraclePasswordLength = 30
const displayNameLimit = 10

func pathRoleCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRoleCreateRead,
		},

		HelpSynopsis:    pathRoleCreateReadHelpSyn,
		HelpDescription: pathRoleCreateReadHelpDesc,
	}
}

func (b *backend) pathRoleCreateRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.logger.Trace("oracle/pathRoleCreateRead: enter")
	defer b.logger.Trace("oracle/pathRoleCreateRead: exit")

	name := data.Get("name").(string)

	// Get the role
	b.logger.Trace("oracle/pathRoleCreateRead: getting role")
	role, err := b.Role(req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", name)), nil
	}

	// Determine if we have a lease
	b.logger.Trace("oracle/pathRoleCreateRead: getting lease")
	lease, err := b.Lease(req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	// Generate the username, password and expiration. Oracle limits user to 30 characters
	displayName := req.DisplayName
	if len(displayName) > displayNameLimit {
		displayName = displayName[:displayNameLimit]
	}
	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	username := fmt.Sprintf("%s_%s", displayName, strings.Replace(userUUID, "-", "_", -1))
	if len(username) > oracleUsernameLength {
		username = username[:oracleUsernameLength]
	}

	password, err := oraclePasswordRandomString()
	if err != nil {
		return nil, err
	}

	// Get our handle
	b.logger.Trace("oracle/pathRoleCreateRead: getting database handle")
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// Start a transaction
	b.logger.Trace("oracle/pathRoleCreateRead: starting transaction")
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		b.logger.Trace("oracle/pathRoleCreateRead: rolling back transaction")
		tx.Rollback()
	}()

	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(role.SQL, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		b.logger.Trace("oracle/pathRoleCreateRead: preparing statement")
		stmt, err := tx.Prepare(Query(query, map[string]string{
			"name":     username,
			"password": password,
		}))
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		b.logger.Trace("oracle/pathRoleCreateRead: executing statement")
		if _, err := stmt.Exec(); err != nil {
			return nil, err
		}
	}

	// Commit the transaction

	b.logger.Trace("oracle/pathRoleCreateRead: committing transaction")
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Return the secret

	b.logger.Trace("oracle/pathRoleCreateRead: generating secret")
	resp := b.Secret(SecretCredsType).Response(map[string]interface{}{
		"username": username,
		"password": password,
	}, map[string]interface{}{
		"username": username,
		"role":     name,
	})
	resp.Secret.TTL = lease.Lease
	return resp, nil
}

// Oracle passwords: https://asktom.oracle.com/pls/apex/f?p=100:11:0::::P11_QUESTION_ID:595223460734
// o Passwords must be from 1 to 30 characters long.
// o Passwords cannot contain quotation marks.
// o Passwords are not case sensitive.
// o A Password must begin with an alphabetic character.
// o Passwords can contain only alphanumeric characters and the
// underscore (_), dollar sign ($), and pound sign (#). Oracle
// strongly discourages you from using $ and #..
// o A Password cannot be an Oracle reserved word (eg: SELECT).
const (
	firstLetterBytes   = "abcdefghijklmnopqrstuvwxyz" // 26 possibilities
	firstLetterIdxBits = 5
	firstLetterIdxMask = 1<<firstLetterIdxBits - 1
	letterBytes        = "abcdefghijklmnopqrstuvwxyz_1234567890" // 37 possibilities
	letterIdxBits      = 6
	letterIdxMask      = 1<<letterIdxBits - 1
)

func oraclePasswordRandomString() (string, error) {
	result := make([]byte, oraclePasswordLength)
	randomByteReader := bufio.NewReader(rand.Reader)
	characterIndex := 0
	for characterIndex < 1 {
		aByte, err := randomByteReader.ReadByte()
		if err != nil {
			return "", err
		}
		if idx := int(aByte & firstLetterIdxMask); idx < len(firstLetterBytes) {
			result[characterIndex] = firstLetterBytes[idx]
			characterIndex++
		}
	}
	for characterIndex < oraclePasswordLength {
		aByte, err := randomByteReader.ReadByte()
		if err != nil {
			return "", err
		}
		if idx := int(aByte & letterIdxMask); idx < len(letterBytes) {
			result[characterIndex] = letterBytes[idx]
			characterIndex++
		}
	}
	return string(result), nil
}

const pathRoleCreateReadHelpSyn = `
Request database credentials for a certain role.
`

const pathRoleCreateReadHelpDesc = `
This path reads database credentials for a certain role. The
database credentials will be generated on demand and will be automatically
revoked when the lease is up.
`
