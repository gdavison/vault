package oracle

import (
	"database/sql"
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
	"github.com/mitchellh/mapstructure"
	"github.com/tgulacsi/go/orahlp"
	dockertest "gopkg.in/ory-am/dockertest.v3"
)

var (
	dockerInit sync.Once
	pool       *dockertest.Pool
)

func prepareTestContainer(t *testing.T, s logical.Storage, b logical.Backend) (resource *dockertest.Resource, connString string) {
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
		t.Fatalf("Unable to run container")
	}
	port := resource.GetPort("1521/tcp")
	if port == "" {
		t.Fatalf("Unable to get port")
	}

	connString = fmt.Sprintf("system/oracle@localhost:%s/xe", resource.GetPort("1521/tcp"))
	pool.MaxWait = time.Minute * 2
	connErr := pool.Retry(func() error {
		db, err := sql.Open("oci8", connString)
		if err != nil {
			return err
		}
		return db.Ping()
	})

	if connErr != nil {
		t.Fatalf("could not connect to database: %v", connErr)
	}

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
		"connection_string":    "sample_connection_string",
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

	resource, connString := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_string": connString,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, connData, false),
			testAccStepCreateRole(t, "web", testRole, false),
			testAccStepReadCreds(t, b, config.StorageView, "web", connString),
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

	resource, connString := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_string": connString,
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

	resource, connString := prepareTestContainer(t, config.StorageView, b)
	if resource != nil {
		defer cleanupTestContainer(t, resource)
	}
	connData := map[string]interface{}{
		"connection_string": connString,
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

	// Build a client and verify that the credentials work
	_, _, link := orahlp.SplitDSN(connString)

	conn := fmt.Sprintf("%s/%s@%s", d.Username, d.Password, link)

	// According to the database/sql specification, Open() is not guaranteed to connect
	// to the database, but Ping() is. oci8 does currently, but test "properly" in case
	// that changes.
	db, err := sql.Open("oci8", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}

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
			t.Fatalf("Error on renew: %#v", *resp)
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
			t.Fatalf("Error on revoke: %#v", *resp)
		}
	}

	err = db.Ping()
	if err == nil {
		t.Fatal("expected failure on existing connection after revocation")
	}

	// According to the database/sql specification, Open() is not guaranteed to connect
	// to the database, but Ping() is. oci8 does currently, but test "properly" in case
	// that changes.
	db2, err := sql.Open("oci8", conn)
	if err == nil {
		err = db2.Ping()
		if err == nil {
			t.Fatal("expected failure to connect after revocation")
		}
	}
	db2.Close()
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
