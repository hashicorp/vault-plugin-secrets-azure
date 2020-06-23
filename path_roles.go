package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesStoragePath = "roles"

	// applicationTypeStatic for when a role is configured with an application_object_id (i.e. the application is managed externally)
	applicationTypeStatic = "static"

	// applicationTypeDynamic for when a role is configured without an application_object_id
	applicationTypeDynamic = "dynamic"

	credentialTypeSP = 0
)

// roleEntry is a Vault role construct that maps to Azure roles or Applications
type roleEntry struct {
	CredentialType      int           `json:"credential_type"` // Reserved. Always SP at this time.
	AzureRoles          []*AzureRole  `json:"azure_roles"`
	AzureGroups         []*AzureGroup `json:"azure_groups"`
	ApplicationID       string        `json:"application_id"`
	ApplicationObjectID string        `json:"application_object_id"`
	TTL                 time.Duration `json:"ttl"`
	MaxTTL              time.Duration `json:"max_ttl"`
	PermanentlyDelete   bool          `json:"permanently_delete"`

	ApplicationType    string             `json:"application_type"`
	ServicePrincipalID string             `json:"service_principal_id"`
	Credentials        *ClientCredentials `json:"credentials"`
}

type ClientCredentials struct {
	KeyId    string `json:"key_id"`
	Password string `json:"password"`
}

// AzureRole is an Azure Role (https://docs.microsoft.com/en-us/azure/role-based-access-control/overview) applied
// to a scope. RoleName and RoleID are both traits of the role. RoleID is the unique identifier, but RoleName is
// more useful to a human (thought it is not unique).
type AzureRole struct {
	RoleName string `json:"role_name"` // e.g. Owner
	RoleID   string `json:"role_id"`   // e.g. /subscriptions/e0a207b2-.../providers/Microsoft.Authorization/roleDefinitions/de139f84-...
	Scope    string `json:"scope"`     // e.g. /subscriptions/e0a207b2-...

	RoleAssignmentID string `json:"role_assignment_id,omitempty"` // e.g. /subscriptions/e0a207b2-.../providers/Microsoft.Authorization/roleAssignments/de139f84-...
}

// AzureGroup is an Azure Active Directory Group
// (https://docs.microsoft.com/en-us/azure/role-based-access-control/overview).
// GroupName and ObjectID are both traits of the group. ObjectID is the unique
// identifier, but GroupName is more useful to a human (though it is not
// unique).
type AzureGroup struct {
	GroupName string `json:"group_name"` // e.g. MyGroup
	ObjectID  string `json:"object_id"`  // e.g. 90820a30-352d-400f-89e5-2ca74ac14333
}

func pathsRole(b *azureSecretBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
				},
				"application_object_id": {
					Type:        framework.TypeString,
					Description: "Application Object ID to use for static service principal credentials.",
				},
				"azure_roles": {
					Type:        framework.TypeString,
					Description: "JSON list of Azure roles to assign.",
				},
				"azure_groups": {
					Type:        framework.TypeString,
					Description: "JSON list of Azure groups to add the service principal to.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time a service principal. If not set or set to 0, will use system default.",
				},
				"permanently_delete": {
					Type:        framework.TypeBool,
					Description: "Indicates whether new application objects should be permanently deleted. If not set, objects will not be permanently deleted.",
					Default:     false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleUpdate,
				logical.UpdateOperation: b.pathRoleUpdate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			HelpSynopsis:    roleHelpSyn,
			HelpDescription: roleHelpDesc,
			ExistenceCheck:  b.pathRoleExistenceCheck,
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
// for the given credential type.
//
// Dynamic Service Principal:
//   Azure roles are checked for existence. The Azure role lookup step will allow the
//   operator to provide a role name or ID. ID is unambigious and will be used if provided.
//   Given just role name, a search will be performed and if exactly one match is found,
//   that role will be used.

//	Azure groups are checked for existence. The Azure groups lookup step will allow the
//	operator to provide a groups name or ID. ID is unambigious and will be used if provided.
//	Given just group name, a search will be performed and if exactly one match is found,
//	that group will be used.
//
// Static Service Principal:
//
//	The provided Application Object ID is checked for existence.
func (b *azureSecretBackend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp *logical.Response

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// load or create role
	name := d.Get("name").(string)

	lock := locksutil.LockForKey(b.appLocks, name)
	lock.Lock()
	defer lock.Unlock()

	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}

	var appObjectID string
	appObjectIDRaw, appObjectIDRawOk := d.GetOk("application_object_id")
	if appObjectIDRawOk {
		appObjectID = appObjectIDRaw.(string)
	}

	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = &roleEntry{
			ApplicationObjectID: appObjectID,
			AzureGroups:         []*AzureGroup{},
			AzureRoles:          []*AzureRole{},
			CredentialType:      credentialTypeSP,
		}

		if role.ApplicationObjectID == "" {
			role.ApplicationType = applicationTypeDynamic
		} else {
			role.ApplicationType = applicationTypeStatic
		}
	} else {
		// Ensure the application_object_id doesn't change. Effectively also ensure that static and dynamic
		// roles remain as static or dynamic, respectively.
		if appObjectIDRawOk && appObjectID != role.ApplicationObjectID {
			return logical.ErrorResponse("the role's application_object_id cannot be updated/removed (recreate role)"), nil
		}
	}

	// load and validate TTLs
	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// load and verify deletion options
	if permanentlyDeleteRaw, ok := d.GetOk("permanently_delete"); ok {
		role.PermanentlyDelete = permanentlyDeleteRaw.(bool)
	} else {
		role.PermanentlyDelete = false
	}

	// update and verify Application Object ID if provided
	if appObjectID, ok := d.GetOk("application_object_id"); ok {
		role.ApplicationObjectID = appObjectID.(string)
	}

	if role.ApplicationObjectID != "" {
		app, err := client.provider.GetApplication(ctx, role.ApplicationObjectID)
		if err != nil {
			return nil, fmt.Errorf("error loading Application: %w", err)
		}
		role.ApplicationID = to.String(app.AppID)

		if role.PermanentlyDelete {
			return logical.ErrorResponse("permanently_delete must be false if application_object_id is provided"), nil
		}
	}

	// Parse the Azure roles
	var requestedRoles []*AzureRole
	if roles, ok := d.GetOk("azure_roles"); ok {
		parsedRoles := make([]*AzureRole, 0) // non-nil to avoid a "missing roles" error later

		err := jsonutil.DecodeJSON([]byte(roles.(string)), &parsedRoles)
		if err != nil {
			return logical.ErrorResponse("error parsing Azure roles '%s': %s", roles.(string), err.Error()), nil
		}
		requestedRoles = parsedRoles
	}

	// Parse the Azure groups
	var requestedGroups []*AzureGroup
	if groups, ok := d.GetOk("azure_groups"); ok {
		parsedGroups := make([]*AzureGroup, 0) // non-nil to avoid a "missing groups" error later

		err := jsonutil.DecodeJSON([]byte(groups.(string)), &parsedGroups)
		if err != nil {
			return logical.ErrorResponse("error parsing Azure groups '%s': %s", groups.(string), err.Error()), nil
		}
		requestedGroups = parsedGroups
	}

	// update and verify Azure roles, including looking up each role by ID or name.
	roleSet := make(map[string]bool)
	for _, r := range requestedRoles {
		var roleDef authorization.RoleDefinition
		if r.RoleID != "" {
			roleDef, err = client.provider.GetRoleDefinitionByID(ctx, r.RoleID)
			if err != nil {
				if strings.Contains(err.Error(), "RoleDefinitionDoesNotExist") {
					return logical.ErrorResponse("no role found for role_id: '%s'", r.RoleID), nil
				}
				return nil, fmt.Errorf("unable to lookup Azure role: %w", err)
			}
		} else {
			defs, err := client.findRoles(ctx, r.RoleName)
			if err != nil {
				return nil, fmt.Errorf("unable to lookup Azure role: %w", err)
			}
			if l := len(defs); l == 0 {
				return logical.ErrorResponse("no role found for role_name: '%s'", r.RoleName), nil
			} else if l > 1 {
				return logical.ErrorResponse("multiple matches found for role_name: '%s'. Specify role by ID instead.", r.RoleName), nil
			}
			roleDef = defs[0]
		}

		roleDefID := to.String(roleDef.ID)
		roleDefName := to.String(roleDef.RoleName)

		r.RoleName, r.RoleID = roleDefName, roleDefID

		rsKey := r.RoleID + "||" + r.Scope
		if roleSet[rsKey] {
			return logical.ErrorResponse("duplicate role_id and scope: '%s', '%s'", r.RoleID, r.Scope), nil
		}
		roleSet[rsKey] = true
	}

	// update and verify Azure groups, including looking up each group by ID or name.
	groupSet := make(map[string]bool)
	for _, r := range requestedGroups {
		var groupDef api.Group
		if r.ObjectID != "" {
			groupDef, err = client.provider.GetGroup(ctx, r.ObjectID)
			if err != nil {
				if strings.Contains(err.Error(), "Request_ResourceNotFound") {
					return logical.ErrorResponse("no group found for object_id: '%s'", r.ObjectID), nil
				}
				return nil, fmt.Errorf("unable to lookup Azure group: %w", err)
			}
		} else {
			defs, err := client.findGroups(ctx, r.GroupName)
			if err != nil {
				return nil, fmt.Errorf("unable to lookup Azure group: %w", err)
			}
			if l := len(defs); l == 0 {
				return logical.ErrorResponse("no group found for group_name: '%s'", r.GroupName), nil
			} else if l > 1 {
				return logical.ErrorResponse("multiple matches found for group_name: '%s'. Specify group by ObjectID instead.", r.GroupName), nil
			}
			groupDef = defs[0]
		}

		r.ObjectID = groupDef.ID
		r.GroupName = groupDef.DisplayName

		if groupSet[r.ObjectID] {
			return logical.ErrorResponse("duplicate object_id '%s'", r.ObjectID), nil
		}
		groupSet[r.ObjectID] = true
	}

	if role.ApplicationObjectID == "" && len(requestedRoles) == 0 && len(requestedGroups) == 0 {
		return logical.ErrorResponse("either Azure role definitions, group definitions, or an Application Object ID must be provided"), nil
	}

	if role.ApplicationType == applicationTypeStatic && role.ApplicationID == "" {
		app, err := client.provider.GetApplication(ctx, role.ApplicationObjectID)
		if err != nil {
			return nil, fmt.Errorf("error loading Application: %w", err)
		}
		role.ApplicationID = to.String(app.AppID)
	}

	if role.ApplicationType == applicationTypeDynamic {
		if role.Credentials == nil {
			walID, err := b.createSPSecret(ctx, req.Storage, client, role)
			if err != nil {
				return nil, err
			}

			// SP is fully created so delete the WAL
			if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
				return nil, fmt.Errorf("error deleting WAL: %w", err)
			}
		}

		err, warn := b.configureRoles(ctx, client, role, requestedRoles)
		if err != nil {
			return nil, err
		}
		if warn != nil {
			resp.AddWarning(warn.Error())
		}

		err, warn = b.configureGroups(ctx, client, role, requestedGroups)
		if err != nil {
			return nil, err
		}
		if warn != nil {
			resp.AddWarning(warn.Error())
		}
	} else if role.ApplicationType == applicationTypeStatic {
		if role.Credentials == nil {
			err = b.createStaticSPSecret(ctx, client, role)
			if err != nil {
				return nil, err
			}
		}
	} else {
		return nil, fmt.Errorf("unknown role ApplicationType \"%v\"", role.ApplicationType)
	}

	// save role
	err = saveRole(ctx, req.Storage, role, name)
	if err != nil {
		return nil, fmt.Errorf("error storing role: %w", err)
	}

	return resp, nil
}

func (b *azureSecretBackend) configureGroups(ctx context.Context, client *client, role *roleEntry, requestedGroups []*AzureGroup) (err error, warn error) {
	groupsToAdd := groupSetDifference(requestedGroups, role.AzureGroups)
	groupsToRemove := groupSetDifference(role.AzureGroups, requestedGroups)

	err = client.addGroupMemberships(ctx, role.ServicePrincipalID, groupsToAdd)
	if err != nil {
		return
	}

	warn = client.removeGroupMemberships(ctx, role.ServicePrincipalID, groupsToRemove)
	if warn != nil {
		return
	}

	role.AzureGroups = requestedGroups
	return
}

func (b *azureSecretBackend) configureRoles(ctx context.Context, client *client, role *roleEntry, requestedRoles []*AzureRole) (err error, warn error) {
	rolesToAdd := roleSetDifference(requestedRoles, role.AzureRoles)
	rolesToRemove := roleSetDifference(role.AzureRoles, requestedRoles)

	_, err = client.assignRoles(ctx, role.ServicePrincipalID, rolesToAdd)
	if err != nil {
		return
	}

	warn = client.unassignRoles(ctx, rolesToRemove)
	if warn != nil {
		return
	}

	role.AzureRoles = requestedRoles
	return
}

func (b *azureSecretBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var data = make(map[string]interface{})

	name := d.Get("name").(string)

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	r, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}

	if r == nil {
		return nil, nil
	}

	data["ttl"] = r.TTL / time.Second
	data["max_ttl"] = r.MaxTTL / time.Second
	for _, ar := range r.AzureRoles {
		ar.RoleAssignmentID = ""
	}
	data["azure_roles"] = r.AzureRoles
	data["azure_groups"] = r.AzureGroups
	aoid := ""
	if r.ApplicationType == applicationTypeStatic {
		aoid = r.ApplicationObjectID
	}
	data["application_object_id"] = aoid
	data["permanently_delete"] = r.PermanentlyDelete

	resp := &logical.Response{
		Data: data,
	}
	return resp, nil
}

func (b *azureSecretBackend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

func (b *azureSecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	lock := locksutil.LockForKey(b.appLocks, name)
	lock.Lock()
	defer lock.Unlock()

	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get role %s: %w", name, err)
	}
	if role == nil {
		return nil, nil
	}

	var resp *logical.Response
	switch role.ApplicationType {
	case applicationTypeStatic:
		resp, err = b.staticSPRemove(ctx, req, role)
		if err != nil {
			return &logical.Response{Warnings: []string{"error removing existing Azure app password"}}, err
		}
	case applicationTypeDynamic:
		resp, err = b.spRemove(ctx, req, role, role.PermanentlyDelete)
		if err != nil {
			return &logical.Response{Warnings: []string{"error removing dynamic Azure service principal"}}, err
		}
	default:
		return nil, fmt.Errorf("unable to delete role, unknown role ApplicationType \"%v\"", role.ApplicationType)
	}

	err = req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return resp, nil
}

func (b *azureSecretBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return false, fmt.Errorf("error reading role: %w", err)
	}

	return role != nil, nil
}

func saveRole(ctx context.Context, s logical.Storage, c *roleEntry, name string) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePath, name), c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, name string, s logical.Storage) (*roleEntry, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	role := new(roleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func groupSetDifference(a []*AzureGroup, b []*AzureGroup) []*AzureGroup {
	difference := []*AzureGroup{}

	m := make(map[AzureGroup]bool)
	for _, bVal := range b {
		m[*bVal] = true
	}

	for _, aVal := range a {
		if _, ok := m[*aVal]; !ok {
			difference = append(difference, aVal)
		}
	}

	return difference
}

func roleSetDifference(a []*AzureRole, b []*AzureRole) []*AzureRole {
	difference := []*AzureRole{}

	m := make(map[AzureRole]bool)
	for _, bVal := range b {
		m[*bVal] = true
	}

	for _, aVal := range a {
		if _, ok := m[*aVal]; !ok {
			difference = append(difference, aVal)
		}
	}

	return difference
}

const roleHelpSyn = "Manage the Vault roles used to generate Azure credentials."
const roleHelpDesc = `
This path allows you to read and write roles that are used to generate Azure login
credentials. These roles are associated with either an existing Application, or a set
of Azure roles, which are used to control permissions to Azure resources.

If the backend is mounted at "azure", you would create a Vault role at "azure/roles/my_role",
and request credentials from "azure/creds/my_role".

Each Vault role is configured with the standard ttl parameters and either an
Application Object ID or a combination of Azure groups to make the service
principal a member of, and Azure roles and scopes to assign the service
principal to. During the Vault role creation, any set Azure role, group, or
Object ID will be fetched and verified, and therefore must exist for the request
to succeed. When a user requests credentials against the Vault role, a new
password will be created for the Application if an Application Object ID was
configured. Otherwise, a new service principal will be created and the
configured set of Azure roles are assigned to it and it will be added to the
configured groups.
`
const roleListHelpSyn = `List existing roles.`
const roleListHelpDesc = `List existing roles by name.`
