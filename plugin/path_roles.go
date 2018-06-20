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
	rolePrefix = "roles"
)

type Role struct {
	CredentialType string        `json:"credential_type"`
	Roles          []*azureRole  `json:"roles"`
	DefaultTTL     time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
}

type azureRole struct {
	RoleName string `json:"role_name"`
	RoleID   string `json:"role_id"`
	Scope    string `json:"scope"`
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
					Description: "Azure roles to assign",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If <= 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time a service principal. If <= 0, will use system default.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "TBD",
			HelpDescription: "TBD",
		},
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    "TBD",
			HelpDescription: "TBD",
		},
	}

}

// pathRoleCreateUpdate creates or updates Vault roles. Basic validity check are made to verify that the
// provided fields meet the requirements for the secret type. There are no checks of the validity of the Azure
// data itself (e.g. that identities or roles exist, etc.)
func (b *azureSecretBackend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	if stRaw, ok := d.GetOk("credential_type"); ok {
		role.CredentialType = stRaw.(string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.DefaultTTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roles, ok := d.GetOk("roles"); ok {
		parsedRoles := []*azureRole{} // non-nil to suppress the "missing roles" error later

		err := jsonutil.DecodeJSON([]byte(roles.(string)), &parsedRoles)
		if err != nil {
			merr = multierror.Append(merr, errors.New("invalid Azure role definitions"))
		}
		role.Roles = parsedRoles
	}

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

		switch len(roleDefs) {
		case 0:
			return logical.ErrorResponse(
				fmt.Sprintf("no role found for role_name: '%s', role_id: '%s'", r.RoleName, r.RoleID)), nil
		case 1:
		default:
			return logical.ErrorResponse(
				fmt.Sprintf("multiple matches found for role_name: '%s'", r.RoleName)), nil
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
	roles, err := req.Storage.List(ctx, rolePrefix+"/")
	if err != nil {
		return nil, errwrap.Wrapf("error listing roles: {{err}}", err)
	}
	_ = roles
	return logical.ListResponse(roles), nil
}

func (b *azureSecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	err := req.Storage.Delete(ctx, rolePrefix+"/"+nameRaw.(string))
	if err != nil {
		return nil, errwrap.Wrapf("error deleting role: {{err}}", err)
	}
	return nil, nil
}

func (b *azureSecretBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return false, errors.New("name is required")
	}

	cr, err := getRole(ctx, nameRaw.(string), req.Storage)
	if err != nil {
		return false, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	return cr != nil, nil
}

func saveRole(ctx context.Context, c *Role, name string, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolePrefix, name), c)
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

//func (b *azureSecretBackend) lookupRole(ctx context.Context, c *azureClient, role *azureRole) error {
//	r, err := c.searchRole(role.RoleName)
//	if err != nil {
//		return err
//	}
//	fmt.Println(*r[0].ID)
//	fmt.Println(*r[0].Name)
//	return nil
//}

//func validateTTL(passwordConf *passwordConf, fieldData *framework.FieldData) (int, error) {
//	ttl := fieldData.Get("ttl").(int)
//	if ttl == 0 {
//		ttl = passwordConf.TTL
//	}
//	if ttl > passwordConf.MaxTTL {
//		return 0, fmt.Errorf("requested ttl of %d seconds is over the max ttl of %d seconds", ttl, passwordConf.MaxTTL)
//	}
//	if ttl < 0 {
//		return 0, fmt.Errorf("ttl can't be negative")
//	}
//	return ttl, nil
//}
