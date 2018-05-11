package azuresecrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/logical"
)

const (
	credRolePrefix = "roles/credential" // TODO maybe better with trailing /
)

type azureRole struct {
	RoleID string `json:"role_id"`
	Scope  string `json:"scope"`
}

type CredentialRole struct {
	Name  string      `json:"name"`
	Roles []azureRole `json:"roles"`
}

func newCredentialRole(name, roles string) (*CredentialRole, error) {
	var parsedRoles []azureRole

	if err := json.Unmarshal([]byte(roles), &parsedRoles); err != nil {
		return nil, err
	}

	// Validate, or save here instead?

	return &CredentialRole{
		Name:  name,
		Roles: parsedRoles,
	}, nil
}

func (c *CredentialRole) validate() error {
	return nil
}

func (c *CredentialRole) save(ctx context.Context, s logical.Storage) error {
	if err := c.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", credRolePrefix, c.Name), c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *azureSecretBackend) getCredentialRole(ctx context.Context, name string, s logical.Storage) (*CredentialRole, error) {
	b.Logger().Debug("", "name", name)
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", credRolePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := new(CredentialRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}
