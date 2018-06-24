package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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
				Description: "Name of the Vault role",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathSPRead,
		},
		HelpSynopsis:    pathServicePrincipalHelpSyn,
		HelpDescription: pathServicePrincipalHelpDesc,
	}
}

// pathSPRead generates Azure an service principal and credentials.
//
// This is a multistep process of:
//   1. Create an Azure application
//   2. Create a service principal associated with the new App
//   3. Assign roles
func (b *azureSecretBackend) pathSPRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	roleName := d.Get("role").(string)
	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exists", roleName)), nil
	}

	// Create the App, which is the top level object to be tracked in the secret
	// and deleted upon revocation. If any subsequent step fails, the App is deleted.
	app, err := c.createApp(ctx)
	if err != nil {
		return nil, err
	}

	// Create the SP. Vault is responsible for revocation, but the time-bound password credentials
	// enforced by Azure are a good defense-in-depth measure. The credentials will expire a short
	/// time after the MaxTTL, even if Vault fails to revoke them for any reason.
	sp, password, err := c.createSP(ctx, app, cfg.MaxTTL+5*time.Minute)
	if err != nil {
		c.deleteApp(ctx, *app.ObjectID)
		return nil, err
	}

	raIDs, err := c.assignRoles(ctx, sp, role.Roles)
	if err != nil {
		c.deleteApp(ctx, *app.ObjectID)
		return nil, err
	}

	resp := b.Secret(SecretTypeSP).Response(map[string]interface{}{
		"client_id":     *app.AppID,
		"client_secret": password,
	}, map[string]interface{}{
		"appObjectID":       *app.ObjectID,
		"roleAssignmentIDs": raIDs,
		"role":              roleName,
	})

	updateTTLs(resp.Secret, role, cfg)

	return resp, nil
}

func (b *azureSecretBackend) spRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("internal data not found")
	}

	role, err := getRole(ctx, roleRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	updateTTLs(resp.Secret, role, cfg)

	return resp, nil
}

func (b *azureSecretBackend) spRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := new(logical.Response)

	appObjectIDRaw, ok := req.Secret.InternalData["appObjectID"]
	if !ok {
		return nil, errors.New("internal data not found")
	}

	appObjectID := appObjectIDRaw.(string)

	var raIDs []string
	if req.Secret.InternalData["roleAssignmentIDs"] != nil {
		for _, v := range req.Secret.InternalData["roleAssignmentIDs"].([]interface{}) {
			raIDs = append(raIDs, v.(string))
		}
	}

	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error during revoke: {{err}}", err)
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

// updateTTLs sets a secret's TTLs, giving preference to role TTLs if present.
func updateTTLs(secret *logical.Secret, role *Role, cfg *azureConfig) {
	if role != nil && role.DefaultTTL > 0 {
		secret.TTL = role.DefaultTTL
	} else {
		secret.TTL = cfg.DefaultTTL
	}

	if role != nil && role.MaxTTL > 0 {
		secret.MaxTTL = role.MaxTTL
	} else {
		secret.MaxTTL = cfg.MaxTTL
	}
}

const pathServicePrincipalHelpSyn = `
Request Service Principal credentials for a given Vault role.
`

const pathServicePrincipalHelpDesc = `
This path creates a Service Principal and assigns Azure roles for a
given Vault role, returning the associated login credentials. The
Service Principal will be automatically deleted when the lease has expired.
`
