package azuresecrets

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/version"
	msGraphAuth "github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
)

// AzureProvider is an interface to access underlying Azure client objects and supporting services.
// Where practical the original function signature is preserved. client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	ApplicationsClient
	ServicePrincipalsClient
	ADGroupsClient
	RoleAssignmentsClient
	RoleDefinitionsClient
}

type ApplicationsClient interface {
	CreateApplication(ctx context.Context, parameters msgraph.Application) (*msgraph.Application, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) error
	GetApplication(ctx context.Context, applicationObjectID string) (*msgraph.Application, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, credential msgraph.PasswordCredential) (newCredential *msgraph.PasswordCredential, err error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyId string) (err error)
}

type ServicePrincipalsClient interface {
	CreateServicePrincipal(ctx context.Context, parameters msgraph.ServicePrincipal) (*msgraph.ServicePrincipal, error)
	DeleteServicePrincipal(ctx context.Context, objectID string) error
	GetServicePrincipal(ctx context.Context, objectID string) (*msgraph.ServicePrincipal, error)
}

type ADGroupsClient interface {
	AddGroupMember(ctx context.Context, group *msgraph.Group) (err error)
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (err error)
	GetGroup(ctx context.Context, objectID string) (result *msgraph.Group, err error)
	ListGroups(ctx context.Context, filter string) (result *[]msgraph.Group, err error)
}

type RoleAssignmentsClient interface {
	CreateRoleAssignment(
		ctx context.Context,
		scope string,
		roleAssignmentName string,
		parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleID string) (authorization.RoleAssignment, error)
}

type RoleDefinitionsClient interface {
	ListRoles(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
	GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error)
}

// provider is a concrete implementation of AzureProvider. In most cases it is a simple passthrough
// to the appropriate client object. But if the response requires processing that is more practical
// at this layer, the response signature may different from the Azure signature.
type provider struct {
	settings *clientSettings

	appClient    *msgraph.ApplicationsClient
	spClient     *msgraph.ServicePrincipalsClient
	groupsClient *msgraph.GroupsClient
	raClient     *authorization.RoleAssignmentsClient
	rdClient     *authorization.RoleDefinitionsClient
}

// newAzureProvider creates an azureProvider, backed by Azure client objects for underlying services.
func newAzureProvider(settings *clientSettings) (AzureProvider, error) {
	var userAgent string
	if settings.PluginEnv != nil {
		userAgent = useragent.PluginString(settings.PluginEnv, "azure-secrets")
	} else {
		userAgent = useragent.String()
	}

	// Sets a unique ID in the user-agent
	// Normal user-agent looks like this:
	//
	// Vault/1.6.0 (+https://www.vaultproject.io/; azure-secrets; go1.15.7)
	//
	// Here we append a unique code if it's an enterprise version, where
	// VersionMetadata will contain a non-empty string like "ent" or "prem".
	// Otherwise use the default identifier for OSS Vault. The end result looks
	// like so:
	//
	// Vault/1.6.0 (+https://www.vaultproject.io/; azure-secrets; go1.15.7; b2c13ec1-60e8-4733-9a76-88dbb2ce2471)
	vaultIDString := "; 15cd22ce-24af-43a4-aa83-4c1a36a4b177)"
	ver := version.GetVersion()
	if ver.VersionMetadata != "" {
		vaultIDString = "; b2c13ec1-60e8-4733-9a76-88dbb2ce2471)"
	}
	userAgent = strings.Replace(userAgent, ")", vaultIDString, 1)

	msGraphAuthConfig := msGraphAuth.Config{
		Environment:            settings.MsGraphEnvironment,
		TenantID:               settings.TenantID,
		ClientID:               settings.ClientID,
		ClientSecret:           settings.ClientSecret,
		EnableClientSecretAuth: true,
		EnableMsiAuth:          true,
	}

	msGraphAuthorizer, err := msGraphAuthConfig.NewAuthorizer(context.TODO(), msGraphAuth.MsGraph)
	if err != nil {
		return nil, err
	}

	appClient := msgraph.NewApplicationsClient(settings.TenantID)
	appClient.BaseClient.Authorizer = msGraphAuthorizer
	appClient.BaseClient.DisableRetries = false
	appClient.BaseClient.UserAgent = userAgent

	spClient := msgraph.NewServicePrincipalsClient(settings.TenantID)
	spClient.BaseClient.Authorizer = msGraphAuthorizer
	spClient.BaseClient.DisableRetries = false
	spClient.BaseClient.UserAgent = userAgent

	groupsClient := msgraph.NewGroupsClient(settings.TenantID)
	groupsClient.BaseClient.Authorizer = msGraphAuthorizer
	groupsClient.BaseClient.DisableRetries = false
	groupsClient.BaseClient.UserAgent = userAgent

	// build clients that use the Resource Manager endpoint
	var authorizer autorest.Authorizer
	if settings.ClientID != "" && settings.ClientSecret != "" && settings.TenantID != "" {
		config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
		config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
		config.Resource = settings.Environment.ResourceManagerEndpoint
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	} else {
		config := auth.NewMSIConfig()
		config.Resource = settings.Environment.ResourceManagerEndpoint
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	}

	raClient := authorization.NewRoleAssignmentsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, settings.SubscriptionID)
	raClient.Authorizer = authorizer
	raClient.AddToUserAgent(userAgent)

	rdClient := authorization.NewRoleDefinitionsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, settings.SubscriptionID)
	rdClient.Authorizer = authorizer
	rdClient.AddToUserAgent(userAgent)

	p := &provider{
		settings: settings,

		appClient:    appClient,
		spClient:     spClient,
		groupsClient: groupsClient,
		raClient:     &raClient,
		rdClient:     &rdClient,
	}

	return p, nil
}

// CreateApplication create a new Azure application object.
func (p *provider) CreateApplication(ctx context.Context, parameters msgraph.Application) (application *msgraph.Application, err error) {
	application, _, err = p.appClient.Create(ctx, parameters)
	return
}

// GetApplication retrieves an Application object
func (p *provider) GetApplication(ctx context.Context, applicationObjectID string) (application *msgraph.Application, err error) {
	application, _, err = p.appClient.Get(ctx, applicationObjectID, odata.Query{})
	return
}

// DeleteApplication deletes an Azure application object.
func (p *provider) DeleteApplication(ctx context.Context, applicationObjectID string) (err error) {
	_, err = p.appClient.Delete(ctx, applicationObjectID)
	return
}

// AddApplicationPassword adds a new client secret to an application
func (p *provider) AddApplicationPassword(ctx context.Context, applicationObjectID string, credential msgraph.PasswordCredential) (newCredential *msgraph.PasswordCredential, err error) {
	newCredential, _, err = p.appClient.AddPassword(ctx, applicationObjectID, credential)
	return
}

// RemoveApplicationPassword removes a client secret from an application
func (p *provider) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyId string) (err error) {
	_, err = p.appClient.RemovePassword(ctx, applicationObjectID, keyId)
	return
}

// CreateServicePrincipal creates a new Azure service principal.
// An Application must be created prior to calling this and pass in parameters.
func (p *provider) CreateServicePrincipal(ctx context.Context, parameters msgraph.ServicePrincipal) (servicePrincipal *msgraph.ServicePrincipal, err error) {
	servicePrincipal, _, err = p.spClient.Create(ctx, parameters)
	return
}

// GetServicePrincipal retrieves a ServicePrincipal object
func (p *provider) GetServicePrincipal(ctx context.Context, objectID string) (sp *msgraph.ServicePrincipal, err error) {
	sp, _, err = p.spClient.Get(ctx, objectID, odata.Query{})
	return
}

// DeleteServicePrincipal deletes an Azure service principal
func (p *provider) DeleteServicePrincipal(ctx context.Context, objectID string) (err error) {
	_, err = p.spClient.Delete(ctx, objectID)
	return
}

// ListRoles like all Azure roles with a scope (often subscription).
func (p *provider) ListRoles(ctx context.Context, scope string, filter string) (result []authorization.RoleDefinition, err error) {
	page, err := p.rdClient.List(ctx, scope, filter)

	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}

// GetRoleByID fetches the full role definition given a roleID.
func (p *provider) GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error) {
	return p.rdClient.GetByID(ctx, roleID)
}

// CreateRoleAssignment assigns a role to a service principal.
func (p *provider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return p.raClient.Create(ctx, scope, roleAssignmentName, parameters)
}

// GetRoleAssignmentByID fetches the full role assignment info given a roleAssignmentID.
func (p *provider) GetRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.GetByID(ctx, roleAssignmentID)
}

// DeleteRoleAssignmentByID deletes a role assignment.
func (p *provider) DeleteRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.DeleteByID(ctx, roleAssignmentID)
}

// ListRoleAssignments lists all role assignments.
// There is no need for paging; the caller only cares about the the first match and whether
// there are 0, 1 or >1 items. Unpacking here is a simpler interface.
func (p *provider) ListRoleAssignments(ctx context.Context, filter string) ([]authorization.RoleAssignment, error) {
	page, err := p.raClient.List(ctx, filter)

	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}

// AddGroupMember adds a member to a AAD Group.
func (p *provider) AddGroupMember(ctx context.Context, group *msgraph.Group) (err error) {
	_, err = p.groupsClient.AddMembers(ctx, group)
	return
}

// RemoveGroupMember removes a member from a AAD Group.
func (p *provider) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (err error) {
	membersToRemove := []string{memberObjectID}
	_, err = p.groupsClient.RemoveMembers(ctx, groupObjectID, &membersToRemove)
	return
}

// GetGroup gets group information from the directory.
func (p *provider) GetGroup(ctx context.Context, objectID string) (result *msgraph.Group, err error) {
	result, _, err = p.groupsClient.Get(ctx, objectID, odata.Query{})
	return
}

// ListGroups gets list of groups for the current tenant.
func (p *provider) ListGroups(ctx context.Context, filter string) (result *[]msgraph.Group, err error) {
	result, _, err = p.groupsClient.List(ctx, odata.Query{Filter: filter})
	return
}
