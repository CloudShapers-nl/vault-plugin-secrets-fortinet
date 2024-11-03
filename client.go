package vault_plugin_secrets_fortinet

import (
	"errors"
	fortiAuth "github.com/fortinetdev/forti-sdk-go/fortios/auth"
	forticlient "github.com/fortinetdev/forti-sdk-go/fortios/sdkcore"
	"net/http"
)

// fortigateClient creates an object storing
// the FortiSDKClient
type fortigateClient struct {
	*forticlient.FortiSDKClient
}

// newClient creates a new client to access FortiOS
// and expose it for any secrets or roles to use.
func newClient(config *fortigateConfig) (*fortigateClient, error) {
	if config == nil {
		return nil, errors.New("client config was nil")
	}

	if config.Hostname == "" {
		return nil, errors.New("client hostname was not defined")
	}

	if config.Token == "" {
		return nil, errors.New("client token was not defined")
	}

	auth := &fortiAuth.Auth{Hostname: config.Hostname, Token: config.Token, Insecure: &config.Insecure}
	c, err := forticlient.NewClient(auth, &http.Client{})
	if err != nil {
		return nil, err
	}
	return &fortigateClient{c}, nil
}
