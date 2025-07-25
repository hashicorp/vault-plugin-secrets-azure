// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathStaticRole = "static-roles/"

	paramRoleName            = "name"
	paramApplicationObjectID = "application_object_id"
)

type azureStaticRole struct {
	ApplicationObjectID string `json:"application_object_id"`
}

func pathStaticRoles(b *azureSecretBackend) *framework.Path {
	fields := map[string]*framework.FieldSchema{
		paramRoleName: {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the static role. Must be a lowercase string.",
			Required:    true,
		},
		paramApplicationObjectID: {
			Type:        framework.TypeString,
			Description: "The Azure AD application object ID whose credentials Vault will manage.",
			Required:    true,
		},
	}

	return &framework.Path{
		Pattern: pathStaticRole + framework.GenericNameRegex("name"),
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathStaticRoleCreateUpdate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathStaticRoleCreateUpdate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticRoleRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathStaticRoleDelete,
			},
		},
		ExistenceCheck:  b.staticRoleExists,
		HelpSynopsis:    pathStaticRolesHelpSyn,
		HelpDescription: pathStaticRolesHelpDesc,
	}
}

func (b *azureSecretBackend) staticRoleExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get(paramRoleName).(string)
	if name == "" {
		return false, fmt.Errorf("missing required field 'name'")
	}

	path := pathStaticRole + name
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *azureSecretBackend) pathStaticRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading role from storage: %w", err)
	}
	if role == nil {
		role = &azureStaticRole{}
	}

	if v, ok := data.GetOk(paramApplicationObjectID); ok {
		role.ApplicationObjectID = v.(string)
	}
	if role.ApplicationObjectID == "" {
		return logical.ErrorResponse("missing required field 'application_object_id'"), nil
	}

	entry, err := logical.StorageEntryJSON(pathStaticRole+name, role)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize role: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to save role to storage: %w", err)
	}

	return nil, nil
}

func (b *azureSecretBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			paramApplicationObjectID: role.ApplicationObjectID,
		},
	}

	return resp, nil
}

func (b *azureSecretBackend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(paramRoleName).(string)

	if err := req.Storage.Delete(ctx, pathStaticRole+name); err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

func (b *azureSecretBackend) getStaticRole(ctx context.Context, s logical.Storage, name string) (*azureStaticRole, error) {
	entry, err := s.Get(ctx, pathStaticRole+name)
	if err != nil || entry == nil {
		return nil, err
	}

	var role azureStaticRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

const pathStaticRolesHelpSyn = `
Manage static roles for Azure Secrets.
`

const pathStaticRolesHelpDesc = `
This path lets you manage static roles for Azure secret backend.
Static roles are used to manage long-lived Azure AD application credentials.
`
