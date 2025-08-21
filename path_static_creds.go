package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathStaticCreds = "static-creds/"

	pathRotateRole = "rotate-role/"
)

type azureStaticCred struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	SecretID     string `json:"secret_id"`
	Expiration   string `json:"expiration"`
}

func pathStaticRoleCreds(b *azureSecretBackend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		paramRoleName: {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the static role. Must be a lowercase string.",
			Required:    true,
		},
	}

	return []*framework.Path{
		{
			Pattern: pathStaticCreds + framework.GenericNameRegex("name"),
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticCredRead,
				},
			},
			HelpSynopsis:    pathStaticCredReadHelpSyn,
			HelpDescription: pathStaticCredReadHelpDesc,
		},
		{
			Pattern: pathRotateRole + framework.GenericNameRegex("name"),
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathStaticCredRotate,
				},
			},
			HelpSynopsis:    pathStaticCredRotateHelpSyn,
			HelpDescription: pathStaticCredRotateHelpDesc,
		},
	}
}

func (b *azureSecretBackend) pathStaticCredRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	// ensure a valid role was requested for rotation
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading role from storage: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role not found in storage")
	}

	// get the credential info associated with the role
	cred, err := getStaticCred(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading credential from storage: %w", err)
	}
	if cred == nil {
		return nil, fmt.Errorf("credential not found in storage")
	}

	// prevents a race condition of multiple rotation requests are running for the same role
	lock := locksutil.LockForKey(b.appLocks, role.ApplicationObjectID)
	lock.Lock()
	defer lock.Unlock()

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// determine whether we should use the system default or the role's TTL for the new credential
	var expiration time.Duration
	if role.TTL > 0 {
		expiration = role.TTL
	} else {
		expiration = spExpiration
	}

	// revoke the old credential
	err = client.deleteAppPassword(ctx, role.ApplicationObjectID, cred.SecretID)
	if err != nil {
		return nil, err
	}

	// provision a new static credential to save
	newCred, err := b.provisionStaticCred(ctx, client, role.ApplicationObjectID, expiration)
	if err != nil {
		return nil, err
	}

	err = saveStaticCred(ctx, req.Storage, newCred, name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *azureSecretBackend) pathStaticCredRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	cred, err := getStaticCred(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}
	if cred == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":     cred.ClientID,
			"secret_id":     cred.SecretID,
			"client_secret": cred.ClientSecret,
			"expiration":    cred.Expiration,
		},
	}

	return resp, nil
}

// provisions a new credential for a service principal used in an Azure static role
func (b *azureSecretBackend) provisionStaticCred(ctx context.Context, c *client, appObjID string, expiresIn time.Duration) (*azureStaticCred, error) {
	// retrieve the Azure application
	app, err := c.provider.GetApplication(ctx, appObjID)
	if err != nil {
		return nil, fmt.Errorf("error loading Application: %w", err)
	}

	// provision a new credential with the given expiration
	secretId, password, endDate, err := c.addAppPassword(ctx, appObjID, expiresIn)
	if err != nil {
		return nil, fmt.Errorf("error provisioning new credential for static role: %w", err)
	}

	cred := &azureStaticCred{
		ClientID:     app.AppID,
		ClientSecret: password,
		SecretID:     secretId,
		Expiration:   endDate.Format(time.RFC3339),
	}

	return cred, nil
}

func saveStaticCred(ctx context.Context, s logical.Storage, cred *azureStaticCred, name string) error {
	entry, err := logical.StorageEntryJSON(pathStaticCreds+name, cred)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getStaticCred(ctx context.Context, s logical.Storage, name string) (*azureStaticCred, error) {
	entry, err := s.Get(ctx, pathStaticCreds+name)
	if err != nil || entry == nil {
		return nil, err
	}

	var cred azureStaticCred
	if err := entry.DecodeJSON(&cred); err != nil {
		return nil, err
	}

	return &cred, nil
}

const (
	pathStaticCredReadHelpSyn = `
Read the credentials stored in an Azure static role.
`
	pathStaticCredReadHelpDesc = `
This path lets you read the credentials of a static role for the Azure secret backend.
`

	pathStaticCredRotateHelpSyn = `
Rotate the credentials for an Azure static role.
`
	pathStaticCredRotateHelpDesc = `
This path lets you revoke the current credential associated with an Azure static role and provision a new one.
`
)
