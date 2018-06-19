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
	SecretTypeSP = "service_principal"
)

func secretServicePrincipal(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeSP,
		Renew:  b.spRenew,
		Revoke: b.spRevoke,
	}
}

func pathServicePrincipal(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathSPRead,
			logical.UpdateOperation: b.pathSPRead,
		},
		//HelpSynopsis:    pathTokenHelpSyn,
		//HelpDescription: pathTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathSPRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during service principal create: could not load config")
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	roleName := d.Get("role").(string)
	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exists", roleName)), nil
	}

	if role.CredentialType != SecretTypeSP {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' is not a service principal role", roleName)), nil
	}

	app, err := c.createApp(ctx)
	if err != nil {
		return nil, err
	}

	walID, err := framework.PutWAL(ctx, req.Storage, walTypeCredential, &walCredential{
		AppObjectID: *app.ObjectID,
	})
	if err != nil {
		return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
	}

	sp, secret, err := c.createSP(ctx, app, cfg.MaxTTL)
	if err != nil {
		c.deleteApp(ctx, *app.ObjectID)
		return nil, err
	}

	raIDs, err := c.assignRoles(ctx, sp, role.Roles)
	if err != nil {
		c.deleteApp(ctx, *app.ObjectID)
		return nil, err
	}

	framework.DeleteWAL(ctx, req.Storage, walID)

	resp := b.Secret(SecretTypeSP).Response(map[string]interface{}{
		"client_id":     *app.AppID,
		"client_secret": secret,
	}, map[string]interface{}{
		"appObjectID":       *app.ObjectID,
		"roleAssignmentIDs": raIDs,
	})

	if role.DefaultTTL > 0 {
		resp.Secret.TTL = role.DefaultTTL
	} else {
		resp.Secret.TTL = cfg.DefaultTTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	} else {
		resp.Secret.MaxTTL = cfg.MaxTTL
	}

	return resp, nil
}

func (b *azureSecretBackend) spRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during renew: could not load config")
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = cfg.DefaultTTL
	resp.Secret.MaxTTL = cfg.MaxTTL

	return resp, nil
}

func (b *azureSecretBackend) spRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp *logical.Response

	appObjectID, err := GetInternalString(req, "appObjectID")
	if err != nil {
		return nil, err
	}

	var raIDs []string
	if req.Secret.InternalData["roleAssignmentIDs"] != nil {
		for _, v := range req.Secret.InternalData["roleAssignmentIDs"].([]interface{}) {
			raIDs = append(raIDs, v.(string))
		}
	}

	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during revoke: could not load config")
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return nil, errwrap.Wrapf("error during revoke: {{err}}", err)
	}

	// unassigning roles is effectively a garbage collection operation. Errors will be noted but won't fail the
	// revocation process. Deleting the app, however, *is* required to consider the secret revoked.
	if err := c.unassignRoles(ctx, raIDs); err != nil {
		resp.AddWarning(err.Error())
	}

	err = c.deleteApp(ctx, appObjectID)

	return resp, err
}

func (b *azureSecretBackend) spRollback(ctx context.Context, req *logical.Request, data interface{}) error {
	var entry walCredential

	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return errors.New("error during rollback: could not load config")
	}

	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return err
	}

	return c.deleteApp(ctx, entry.AppObjectID)
}
