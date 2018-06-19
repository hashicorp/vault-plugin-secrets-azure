package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
)

const (
	rolePrefix = "roles"
)

type Role struct {
	CredentialType string        `json:"credential_type"`
	Identity       string        `json:"identity"`
	ResourceGroup  string        `json:"resource_group"`
	Name           string        `json:"name"`
	Roles          []*azureRole  `json:"roles"`
	DefaultTTL     time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
}

type azureRole struct {
	RoleName string `json:"role_name"`
	RoleID   string `json:"role_id"`
	Scope    string `json:"scope"`
}

func saveRole(ctx context.Context, c *Role, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolePrefix, c.Name), c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, name string, s logical.Storage) (*Role, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := new(Role)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}
