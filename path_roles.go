package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	rolesStoragePath = "roles"
)

// Roles is a Vault role construct, now mapping to Azure roles, primarily
type Role struct {
	CredentialType string        `json:"credential_type"` // Reserved. Always "service_principal" at this time.
	Roles          []*azureRole  `json:"roles"`
	DefaultTTL     time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
}

// azureRole is an Azure Role (https://docs.microsoft.com/en-us/azure/role-based-access-control/overview) applied
// to a scope. RoleName and RoleID are both traits of the role. RoleID is the unique identifier, but RoleName is
// more useful to a human (thought it is not unique).
type azureRole struct {
	RoleName string `json:"role_name"` // e.g. Owner
	RoleID   string `json:"role_id"`   // e.g. /subscriptions/e0a207b2-.../providers/Microsoft.Authorization/roleDefinitions/de139f84-...
	Scope    string `json:"scope"`     // e.g. /subscriptions/e0a207b2-...
}

func pathsRole(b *azureSecretBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("roles/%s", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
				},
				"roles": {
					Type:        framework.TypeString,
					Description: "JSON list of Azure roles to assign",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If ttl == 0, use system default",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time a service principal. If max_ttl == 0, use system default",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.UpdateOperation: b.pathRoleUpdate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			HelpSynopsis:    roleHelpSyn,
			HelpDescription: roleHelpDesc,
		},
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    roleListHelpSyn,
			HelpDescription: roleListHelpDesc,
		},
	}

}

// pathRoleUpdate creates or updates Vault roles.
//
// Basic validity check are made to verify that the provided fields meet requirements
// and the Azure roles exist. The Azure role lookup step will all the operator to provide
// a role name or ID.  ID is unambigious and will be used if provided. Given just role name,
// a search will be performed and if exactly one match is found, that role will be used.
func (b *azureSecretBackend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var merr *multierror.Error
	var resp *logical.Response

	// load or create role
	name := d.Get("name").(string)
	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	if role == nil {
		role = &Role{
			CredentialType: SecretTypeSP,
		}
	}

	// update role with any provided parameters
	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.DefaultTTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roles, ok := d.GetOk("roles"); ok {
		parsedRoles := []*azureRole{} // non-nil to avoid a "missing roles" error later

		err := jsonutil.DecodeJSON([]byte(roles.(string)), &parsedRoles)
		if err != nil {
			merr = multierror.Append(merr, errors.New("invalid Azure role definitions"))
		}
		role.Roles = parsedRoles
	}

	// verify Azure roles
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	roleIDs := make(map[string]bool)
	for _, r := range role.Roles {
		roleDefs, err := c.lookupRole(ctx, r.RoleName, r.RoleID)
		if err != nil {
			return nil, errwrap.Wrapf("unable to lookup Azure role: {{err}}", err)
		}

		if l := len(roleDefs); l == 0 {
			return logical.ErrorResponse(
				fmt.Sprintf("no role found for role_name: '%s', role_id: '%s'", r.RoleName, r.RoleID)), nil
		} else if l > 1 {
			return logical.ErrorResponse(
				fmt.Sprintf("multiple matches found for role_name: '%s'. Specify role by ID instead.", r.RoleName)), nil
		}

		rd := roleDefs[0]
		if roleIDs[*rd.ID] {
			return logical.ErrorResponse(fmt.Sprintf("duplicate role_id: '%s'", *rd.ID)), nil
		}
		roleIDs[*rd.ID] = true
		r.RoleName, r.RoleID = *rd.RoleName, *rd.ID
	}

	// validate role definition constraints
	if role.DefaultTTL < 0 {
		merr = multierror.Append(merr, errors.New("ttl < 0"))
	}
	if role.MaxTTL < 0 {
		merr = multierror.Append(merr, errors.New("max_ttl < 0"))
	}
	if role.DefaultTTL > role.MaxTTL && role.MaxTTL != 0 {
		merr = multierror.Append(merr, errors.New("ttl > max_ttl"))
	}

	if role.Roles == nil {
		merr = multierror.Append(merr, errors.New("missing Azure role definitions"))
	}

	if merr.ErrorOrNil() != nil {
		return logical.ErrorResponse(merr.Error()), nil
	}

	// save role
	err = saveRole(ctx, role, name, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error storing role: {{err}}", err)
	}

	return resp, nil
}

func (b *azureSecretBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var data = make(map[string]interface{})

	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	r, err := getRole(ctx, nameRaw.(string), req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	if r == nil {
		return nil, nil
	}

	data["ttl"] = int64(r.DefaultTTL / time.Second)
	data["max_ttl"] = int64(r.MaxTTL / time.Second)
	data["roles"] = r.Roles

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *azureSecretBackend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return nil, errwrap.Wrapf("error listing roles: {{err}}", err)
	}

	return logical.ListResponse(roles), nil
}

func (b *azureSecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, errwrap.Wrapf("error deleting role: {{err}}", err)
	}

	return nil, nil
}

func saveRole(ctx context.Context, c *Role, name string, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePath, name), c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, name string, s logical.Storage) (*Role, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
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

const roleHelpSyn = "Manage the Vault roles used to generate Azure credentials."
const roleHelpDesc = `
This path allows you to read and write roles that are used to generate Azure login
credentials. These roles are associated with Azure roles, which are in turn used to
control permissions to Azure resources.

If the backend is mounted at "azure", you would create a Vault role at "azure/roles/my_role",
and request credentials from "azure/creds/my_role".

Each Vault roles is configured with the standard ttl parameters and a list of Azure
roles and scopes. These Azure roles will be fetched during the Vault role creation
and must exist for the request to succeed. Multiple Azure roles may be specified. When
a used requests credentials against the Vault role, and new service principal is created
and the configured set of Azure roles are assigned to it.
`
const roleListHelpSyn = `List existing roles.`
const roleListHelpDesc = `List existing roles by name.`