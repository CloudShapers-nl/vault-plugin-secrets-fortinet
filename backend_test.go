package vault_plugin_secrets_fortinet

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

const (
	envVarRunAccTests       = "VAULT_ACC"
	envVarFortigateInsecure = "TEST_FORTIGATE_INSECURE"
	envVarFortigateToken    = "TEST_FORTIGATE_TOKEN"
	envVarFortigateHostname = "TEST_FORTIGATE_HOSTNAME"
)

// getTestBackend will construct a test backend object.
func getTestBackend(tb testing.TB) (*fortigateBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*fortigateBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to the Fortigate API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testEnv creates an object to store and track testing resources
type testEnv struct {
	Hostname string
	Token    string
	Insecure bool

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the created API token, for checking rotations
	SecretToken string

	// Tokens tracks the generated tokens, to check on cleanup
	Tokens []string
}

// AddConfig adds the config to the test backend.
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"hostname": e.Hostname,
			"token":    e.SecretToken,
			"insecure": e.Insecure,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// AddUserTokenRole adds a role for the FG API token.
func (e *testEnv) AddUserTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-user-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"admin_profile": "test-profile",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// ReadUserToken retrieves the user token
// based on a Vault role.
func (e *testEnv) ReadUserToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-user-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if token, ok := resp.Data["token"]; ok {
		e.Tokens = append(e.Tokens, token.(string))
	}
	require.NotEmpty(t, resp.Data["token"])

	if e.SecretToken != "" {
		require.NotEmpty(t, e.SecretToken, resp.Data["token"])
	}

	// Collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if token, ok := resp.Secret.InternalData["token"]; ok {
		e.SecretToken = token.(string)
	}
}

// CleanupUserTokens removes the tokens
// when the test completes.
func (e *testEnv) CleanupUserTokens(t *testing.T) {
	if len(e.Tokens) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Tokens))
	}

	//TODO: Implement deletion of API users
}
