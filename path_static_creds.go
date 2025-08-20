package azuresecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathStaticCred = "static-cred/"
)

type azureStaticCred struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func pathStaticRoleCred(b *azureSecretBackend) *framework.Path {
	fields := map[string]*framework.FieldSchema{
		paramRoleName: {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the static role. Must be a lowercase string.",
			Required:    true,
		},
	}

	return &framework.Path{
		Pattern: pathStaticCred + framework.GenericNameRegex("name"),
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathStaticCredRotate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticCredRead,
			},
		},
		HelpSynopsis:    pathStaticCredHelpSyn,
		HelpDescription: pathStaticCredHelpDesc,
	}
}

func (b *azureSecretBackend) pathStaticCredRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading role from storage: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role not found in storage")
	}

	// create and save new azure static credential
	err = b.createAzureStaticCred(ctx, req.Storage, role.ApplicationObjectID, name)
	if err != nil {
		return nil, fmt.Errorf("error rotating static cred: %w", err)
	}

	return nil, nil
}

func (b *azureSecretBackend) createAzureStaticCred(ctx context.Context, s logical.Storage, applicationObjId string, name string) error {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return err
	}

	app, err := client.provider.GetApplication(ctx, applicationObjId)
	if err != nil {
		return fmt.Errorf("error loading Application: %w", err)
	}

	spID, password, _, err := client.createSP(ctx, app, spExpiration)
	if err != nil {
		return err
	}

	cred := &azureStaticCred{
		ClientID:     spID,
		ClientSecret: password,
	}

	err = saveStaticCred(ctx, s, cred, name)
	if err != nil {
		return err
	}

	return nil
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
			"client_secret": cred.ClientSecret,
		},
	}

	return resp, nil
}

func saveStaticCred(ctx context.Context, s logical.Storage, cred *azureStaticCred, name string) error {
	entry, err := logical.StorageEntryJSON(pathStaticCred+name, cred)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getStaticCred(ctx context.Context, s logical.Storage, name string) (*azureStaticCred, error) {
	entry, err := s.Get(ctx, pathStaticCred+name)
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
	pathStaticCredHelpSyn = `
Manage the credentials for an Azure static role.
`
	pathStaticCredHelpDesc = `
This path lets you manage the credentials of static roles for the Azure secret backend.
`
)
