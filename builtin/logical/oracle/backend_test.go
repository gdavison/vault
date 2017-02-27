package oracle

import (
	"database/sql"
	//	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	_ "github.com/mattn/go-oci8"
	"github.com/mitchellh/mapstructure"
	"github.com/tgulacsi/go/orahlp"
	dockertest "gopkg.in/ory-am/dockertest.v3"
)

var (
	dockerInit sync.Once
	pool       *dockertest.Pool
)

func prepareTestContainer(t *testing.T, s logical.Storage, b logical.Backend) (resource *dockertest.Resource, retURL string) {
	if os.Getenv("ORACLE_DSN") != "" {
		return nil, os.Getenv("ORACLE_DSN")
	}

	dockerInit.Do(func() {
		docker := os.Getenv("DOCKER_URL")
		var err error
		pool, err = dockertest.NewPool(docker)
		if err != nil {
			t.Fatalf("can't docker")
		}
	})

	resource, err := pool.Run("wnameless/oracle-xe-11g", "latest", []string{})
	if err != nil {
		t.Fatalf("can't container")
	}
	port := resource.GetPort("1521/tcp")
	if port == "" {
		t.Fatalf("Dammit, no port")
	}

	connURL := fmt.Sprintf("system/oracle@localhost:%s/xe", resource.GetPort("1521/tcp"))
	connErr := pool.Retry(func() error {
		db, err := sql.Open("oci8", connURL)
		if err != nil {
			return err
		}
		return db.Ping()
	})

	if connErr != nil {
		t.Fatalf("could not connect to database: %v", connErr)
	}

	retURL = connURL
	return
}

func cleanupTestContainer(t *testing.T, resource *dockertest.Resource) {
	err := pool.Purge(resource)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBackend_config_connection(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"connection_url":       "sample_connection_url",
		"value":                "",
		"max_open_connections": 9,
		"max_idle_connections": 7,
		"verify_connection":    false,
	}

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	configReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	delete(configData, "verify_connection")
	if !reflect.DeepEqual(configData, resp.Data) {
		t.Fatalf("bad: expected:%#v\nactual:%#v\n", configData, resp.Data)
	}
}

func TestBackend_basic(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	resource, connURL := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_url": connURL,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, connData, false),
			testAccStepCreateRole(t, "web", testRole, false),
			testAccStepReadCreds(t, b, config.StorageView, "web", connURL),
		},
	})
}

func TestBackend_basic_withRevocationSQL(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	resource, connURL := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_url": connURL,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, connData, false),
			testAccStepCreateRoleWithRevocationSQL(t, "web", testRole, revocationSQL, false),
			testAccStepReadCreds(t, b, config.StorageView, "web", connURL),
		},
	})
}

func TestBackend_roleCrud(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	resource, connURL := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_url": connURL,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, connData, false),
			testAccStepCreateRole(t, "web", testRole, false),
			testAccStepReadRole(t, "web", testRole),
			testAccStepDeleteRole(t, "web"),
			testAccStepReadRole(t, "web", ""),
		},
	})
}

func TestBackend_renew_revoke(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(config)
	if err != nil {
		t.Fatal(err)
	}

	resource, connURL := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_url": connURL,
	}

	req := &logical.Request{
		Storage:   config.StorageView,
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data:      connData,
	}
	resp, err := b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	req.Path = path.Join("config/lease")
	req.Data = map[string]interface{}{
		"lease":     "1h",
		"lease_max": "24h",
	}
	resp, err = b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	roleName := "test"

	req.Path = path.Join("roles", roleName)
	req.Data = map[string]interface{}{
		"sql": testRole,
	}
	resp, err = b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	req.Operation = logical.ReadOperation
	req.Path = path.Join("creds", roleName)
	req.DisplayName = "foobar"
	resp, err = b.HandleRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("resp nil")
	}
	if resp.IsError() {
		t.Fatalf("resp is error: %v", resp.Error())
	}

	var d struct {
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}
	if err := mapstructure.Decode(resp.Data, &d); err != nil {
		t.Fatal(err)
	}
	log.Printf("[TRACE] Generated credentials: %v", d)
	log.Printf("[TRACE] Secret: %v", resp.Secret)

	// Build a client and verify that the credentials work
	username, password, link := orahlp.SplitDSN(connURL)
	log.Printf("[TRACE] username: %s, password: %s, link: %s.", username, password, link)

	conn := fmt.Sprintf("%s/%s@%s", d.Username, d.Password, link)
	log.Printf("[TRACE] conn: %s.", conn)
	db, err := sql.Open("oci8", conn)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	resp, err = b.HandleRequest(&logical.Request{
		Operation: logical.RenewOperation,
		Storage:   config.StorageView,
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL:       1 * time.Hour,
				IssueTime: time.Now(),
			},
			InternalData: map[string]interface{}{
				"secret_type": "creds",
				"username":    d.Username,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		if resp.IsError() {
			t.Fatal("Error on renew: %#v", *resp)
		}
	}

	resp, err = b.HandleRequest(&logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   config.StorageView,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"secret_type": "creds",
				"username":    d.Username,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		if resp.IsError() {
			t.Fatal("Error on revoke: %#v", *resp)
		}
	}

	log.Printf("[TRACE] conn: %s.", conn)
	db, err = sql.Open("oci8", conn)
	if err != nil {
		t.Fatal("expected failure to connect after revocation")
	}
	db.Close()
}

func testAccStepConfig(t *testing.T, d map[string]interface{}, expectError bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data:      d,
		ErrorOk:   true,
		Check: func(resp *logical.Response) error {
			if expectError {
				if resp.Data == nil {
					return fmt.Errorf("data is nil")
				}
				var e struct {
					Error string `mapstructure:"error"`
				}
				if err := mapstructure.Decode(resp.Data, &e); err != nil {
					return err
				}
				if len(e.Error) == 0 {
					return fmt.Errorf("expected error, but write succeeded.")
				}
				return nil
			} else if resp != nil && resp.IsError() {
				return fmt.Errorf("got an error response: %v", resp.Error())
			}
			return nil
		},
	}
}

func testAccStepCreateRole(t *testing.T, name string, sql string, expectFail bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      path.Join("roles", name),
		Data: map[string]interface{}{
			"sql": sql,
		},
		ErrorOk: expectFail,
	}
}

func testAccStepCreateRoleWithRevocationSQL(t *testing.T, name, sql, revocationSQL string, expectFail bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      path.Join("roles", name),
		Data: map[string]interface{}{
			"sql":            sql,
			"revocation_sql": revocationSQL,
		},
		ErrorOk: expectFail,
	}
}

func testAccStepDeleteRole(t *testing.T, name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      path.Join("roles", name),
	}
}

func testAccStepReadCreds(t *testing.T, b logical.Backend, s logical.Storage, name string, connURL string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      path.Join("creds", name),
		Check: func(resp *logical.Response) error {
			var d struct {
				Username string `mapstructure:"username"`
				Password string `mapstructure:"password"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			log.Printf("[TRACE] Generated credentials: %v", d)
			return nil
		},
	}
}

////func testAccStepDropTable(t *testing.T, b logical.Backend, s logical.Storage, name string, connURL string) logicaltest.TestStep {
////	return logicaltest.TestStep{
////		Operation: logical.ReadOperation,
////		Path:      path.Join("creds", name),
////		Check: func(resp *logical.Response) error {
////			var d struct {
////				Username string `mapstructure:"username"`
////				Password string `mapstructure:"password"`
////			}
////			if err := mapstructure.Decode(resp.Data, &d); err != nil {
////				return err
////			}
////			log.Printf("[TRACE] Generated credentials: %v", d)
////			conn, err := pq.ParseURL(connURL)
////
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			conn += " timezone=utc"
////
////			db, err := sql.Open("postgres", conn)
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			_, err = db.Exec("DROP TABLE test;")
////			if err != nil {
////				t.Fatal(err)
////			}
////
////			resp, err = b.HandleRequest(&logical.Request{
////				Operation: logical.RevokeOperation,
////				Storage:   s,
////				Secret: &logical.Secret{
////					InternalData: map[string]interface{}{
////						"secret_type": "creds",
////						"username":    d.Username,
////					},
////				},
////			})
////			if err != nil {
////				return err
////			}
////			if resp != nil {
////				if resp.IsError() {
////					return fmt.Errorf("Error on resp: %#v", *resp)
////				}
////			}
////
////			return nil
////		},
////	}
////}

func testAccStepReadRole(t *testing.T, name string, sql string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				if sql == "" {
					return nil
				}

				return fmt.Errorf("bad: %#v", resp)
			}

			var d struct {
				SQL string `mapstructure:"sql"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}

			if d.SQL != sql {
				return fmt.Errorf("bad: %#v", resp)
			}

			return nil
		},
	}
}

const testRole = `
CREATE USER {{name}} IDENTIFIED BY {{password}};
GRANT CONNECT TO {{name}};
GRANT CREATE SESSION TO {{name}};
`

////const testReadOnlyRole = `
////CREATE ROLE "{{name}}" WITH
////  LOGIN
////  PASSWORD '{{password}}'
////  VALID UNTIL '{{expiration}}';
////GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
////GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
////`
////
////const testBlockStatementRole = `
////DO $$
////BEGIN
////   IF NOT EXISTS (SELECT * FROM pg_catalog.pg_roles WHERE rolname='foo-role') THEN
////      CREATE ROLE "foo-role";
////      CREATE SCHEMA IF NOT EXISTS foo AUTHORIZATION "foo-role";
////      ALTER ROLE "foo-role" SET search_path = foo;
////      GRANT TEMPORARY ON DATABASE "postgres" TO "foo-role";
////      GRANT ALL PRIVILEGES ON SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA foo TO "foo-role";
////   END IF;
////END
////$$
////
////CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
////GRANT "foo-role" TO "{{name}}";
////ALTER ROLE "{{name}}" SET search_path = foo;
////GRANT CONNECT ON DATABASE "postgres" TO "{{name}}";
////`
////
////var testBlockStatementRoleSlice = []string{
////	`
////DO $$
////BEGIN
////   IF NOT EXISTS (SELECT * FROM pg_catalog.pg_roles WHERE rolname='foo-role') THEN
////      CREATE ROLE "foo-role";
////      CREATE SCHEMA IF NOT EXISTS foo AUTHORIZATION "foo-role";
////      ALTER ROLE "foo-role" SET search_path = foo;
////      GRANT TEMPORARY ON DATABASE "postgres" TO "foo-role";
////      GRANT ALL PRIVILEGES ON SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA foo TO "foo-role";
////      GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA foo TO "foo-role";
////   END IF;
////END
////$$
////`,
////	`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
////	`GRANT "foo-role" TO "{{name}}";`,
////	`ALTER ROLE "{{name}}" SET search_path = foo;`,
////	`GRANT CONNECT ON DATABASE "postgres" TO "{{name}}";`,
////}

const revocationSQL = `
REVOKE CONNECT FROM {{name}};
REVOKE CREATE SESSION FROM {{name}};
DROP USER {{name}};
`
