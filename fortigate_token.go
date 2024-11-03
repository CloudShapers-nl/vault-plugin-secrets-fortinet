package vault_plugin_secrets_fortinet

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	fortiGateAdminType = "fortigate_token"
)

// fortigateToken defines a secret for the Fortigate admin
type fortigateToken struct {
	Username string `json:"username"`
	Token    string `json:"token"`
	TokenID  string `json:"token_id"`
}

// fortigateToken defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *fortigateBackend) fortigateToken() *framework.Secret {
	return &framework.Secret{
		Type: fortiGateAdminType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: `The username for the admin.`,
			},
			"token": {
				Type:        framework.TypeString,
				Description: `The password for the admin.`,
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func deleteToken(ctx context.Context, c *fortigateClient, username string) error {
	//TODO: Implement API user deletion
	return nil
}

func (b *fortigateBackend) tokenRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	username := ""
	usernameRaw, ok := req.Secret.InternalData["username"]
	if ok {
		username, ok = usernameRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for username in secret internal data")
		}
	}

	if err := deleteToken(ctx, client, username); err != nil {
		return nil, fmt.Errorf("error revoking token: %w", err)
	}
	return nil, nil
}

func createToken(ctx context.Context, c *fortigateClient, username string) (*fortigateToken, error) {
	//TODO: Implement creation of API admin
	tempToken := ""

	tokenID := uuid.New().String()

	return &fortigateToken{
		Username: username,
		TokenID:  tokenID,
		Token:    tempToken,
	}, nil
}

func (b *fortigateBackend) tokenRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
