package azuresecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

const (
	SecretTypeCredential = "credential"
)

func secretCredential(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeCredential,
		Renew:  b.credentialRenew,
		Revoke: b.credentialRevoke,
	}
}

func pathCredential(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("credential/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialRead,
			logical.UpdateOperation: b.pathCredentialRead,
		},
		//HelpSynopsis:    pathTokenHelpSyn,
		//HelpDescription: pathTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathCredentialRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get("role").(string)

	cr, err := b.getCredentialRole(ctx, role, req.Storage)
	if err != nil {
		return nil, err
	}
	if cr == nil {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' does not exists", role)), nil
	}

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during credential create: could not load config")
	}

	c, err := b.newAzureClient()
	if err != nil {
		return nil, err
	}

	app, err := c.createApp()
	if err != nil {
		return nil, err
	}

	walID, err := framework.PutWAL(ctx, req.Storage, walTypeCredential, &walCredential{
		AppObjectID: *app.ObjectID,
	})
	if err != nil {
		return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
	}

	sp, secret, err := c.createSP(app, cfg.MaxTTL)
	if err != nil {
		c.deleteApp(*app.ObjectID)
		return nil, err
	}

	err = c.assignRoles(sp, cr.Roles)
	if err != nil {
		c.deleteApp(*app.ObjectID)
		return nil, err
	}

	framework.DeleteWAL(ctx, req.Storage, walID)

	resp := b.Secret(SecretTypeCredential).Response(map[string]interface{}{
		"client_id":     *app.AppID,
		"client_secret": secret,
	}, map[string]interface{}{
		"appObjectID": *app.ObjectID,
	})

	resp.Secret.TTL = cfg.DefaultTTL
	resp.Secret.MaxTTL = cfg.MaxTTL
	return resp, nil
}

func (b *azureSecretBackend) credentialRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during renew: could not load config")
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = cfg.DefaultTTL
	resp.Secret.MaxTTL = cfg.MaxTTL

	return resp, nil
}

func (b *azureSecretBackend) credentialRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	appObjectID := req.Secret.InternalData["appObjectID"].(string)

	c, err := b.newAzureClient()
	if err != nil {
		return nil, err
	}

	err = c.deleteApp(appObjectID)

	return nil, err
}

func (b *azureSecretBackend) credentialRollback(ctx context.Context, req *logical.Request, data interface{}) error {
	var entry walCredential

	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	c, err := b.newAzureClient()
	if err != nil {
		return err
	}

	return c.deleteApp(entry.AppObjectID)
}
