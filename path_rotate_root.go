package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rotateRootPath       = "rotate-root"
	rootSecretExpiration = ((time.Hour * 24) * 30) * 6
)

func pathRotateRootCredentials(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: rotateRootPath,
		Fields:  map[string]*framework.FieldSchema{},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis: "Request to rotate the root credentials Vault uses for managing Azure.",
		HelpDescription: "This path attempts to rotate the root credentials of the administrator account " +
			"used by Vault to manage Azure.",
	}
}

func (b *azureSecretBackend) pathRotateRootCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	result, err := client.provider.ListApplication(ctx, fmt.Sprintf("appId eq '%s'", client.settings.ClientID))
	if err != nil {
		return nil, err
	}

	if len(result.Values()) != 1 {
		return nil, fmt.Errorf("could not find application ID for root user")
	}
	objID := *result.Values()[0].ObjectID

	_, password, err := client.addAppPassword(ctx, objID, rootSecretExpiration)
	if err != nil {
		return nil, err
	}

	// Write a WAL entry in case write to storage fails
	walID, err := framework.PutWAL(ctx, req.Storage, walRootKey, &walApp{
		AppID:      config.ClientID,
		AppObjID:   objID,
		Expiration: time.Now().Add(maxWALAge),
		Password:   password,
	})
	if err != nil {
		return nil, errwrap.Wrapf("error writing WAL: {{err}}", err)
	}

	config.ClientSecret = password
	err = b.saveConfig(ctx, config, req.Storage)

	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, errwrap.Wrapf("error deleting WAL: {{err}}", err)
	}

	// Respond with a 204.
	return nil, err
}
