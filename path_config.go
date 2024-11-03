package vault_plugin_secrets_fortinet

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// fortigateConfig includes the minimum configuration
// required to instantiate a new FortiOS client.
type fortigateConfig struct {
	Hostname string `json:"hostname"`
	Token    string `json:"token"`
	Insecure bool   `json:"insecure"`
}

// pathConfig extends the Vault API with
// a `/config` endpoint for the backend.
func pathConfig(b *fortigateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"hostname": {
				Type:        framework.TypeString,
				Description: "The hostname of the Fortigate device",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Hostname",
					Sensitive: false,
				},
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Fortigate device's REST API Token",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token",
					Sensitive: true,
				},
			},
			"insecure": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification when connecting to the Fortigate device",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Insecure",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// patchConfigExistenceCheck verifies if the config exists.
func (b *fortigateBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *fortigateBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"hostname": config.Hostname,
			"insecure": config.Insecure,
		},
	}, nil
}

func (b *fortigateBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(fortigateConfig)
	}

	if hostname, ok := data.GetOk("hostname"); ok {
		config.Hostname = hostname.(string)
	} else if createOperation {
		return nil, fmt.Errorf("missing username in configuration")
	}

	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
	} else if createOperation {
		return nil, fmt.Errorf("missing token in configuration")
	}

	if insecure, ok := data.GetOk("insecure"); ok {
		config.Insecure = insecure.(bool)
	} else if createOperation {
		return nil, fmt.Errorf("missing insecure in configuration")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *fortigateBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*fortigateConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(fortigateConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Fortigate backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Fortigate secret backend requires credentials for managing
REST API Tokens issued to users working with the FortiOS API.

This backend requires a REST API Token to communicate with the FortiOS API
and create dynamically issued token.
`
