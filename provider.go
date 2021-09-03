package azuresecrets

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/version"
)

// provider is a concrete implementation of AzureProvider. In most cases it is a simple passthrough
// to the appropriate client object. But if the response requires processing that is more practical
// at this layer, the response signature may different from the Azure signature.
type provider struct {
	settings *clientSettings

	appClient    api.ApplicationsClient
	spClient     *graphrbac.ServicePrincipalsClient
	groupsClient *graphrbac.GroupsClient
	raClient     *authorization.RoleAssignmentsClient
	rdClient     *authorization.RoleDefinitionsClient
}

// newAzureProvider creates an azureProvider, backed by Azure client objects for underlying services.
func newAzureProvider(settings *clientSettings, useMsGraphApi bool, passwords api.Passwords) (api.AzureProvider, error) {
	// build clients that use the GraphRBAC endpoint
	graphAuthorizer, err := getAuthorizer(settings, settings.Environment.GraphEndpoint)
	if err != nil {
		return nil, err
	}

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

	spClient := graphrbac.NewServicePrincipalsClient(settings.TenantID)
	spClient.Authorizer = graphAuthorizer
	spClient.AddToUserAgent(userAgent)

	groupsClient := graphrbac.NewGroupsClient(settings.TenantID)
	groupsClient.Authorizer = graphAuthorizer
	groupsClient.AddToUserAgent(userAgent)

	var appClient api.ApplicationsClient
	if useMsGraphApi {
		graphApiAuthorizer, err := getAuthorizer(settings, api.DefaultGraphMicrosoftComURI)
		if err != nil {
			return nil, err
		}

		msGraphAppClient := api.NewGraphApplicationClient(settings.SubscriptionID)
		msGraphAppClient.Authorizer = graphApiAuthorizer
		msGraphAppClient.AddToUserAgent(userAgent)

		appClient = &msGraphAppClient
	} else {
		aadGraphClient := graphrbac.NewApplicationsClient(settings.TenantID)
		aadGraphClient.Authorizer = graphAuthorizer
		aadGraphClient.AddToUserAgent(userAgent)

		appClient = &api.ActiveDirectoryApplicatinClient{Client: &aadGraphClient, Passwords: passwords}
	}

	// build clients that use the Resource Manager endpoint
	resourceManagerAuthorizer, err := getAuthorizer(settings, settings.Environment.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	raClient := authorization.NewRoleAssignmentsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, settings.SubscriptionID)
	raClient.Authorizer = resourceManagerAuthorizer
	raClient.AddToUserAgent(userAgent)

	rdClient := authorization.NewRoleDefinitionsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, settings.SubscriptionID)
	rdClient.Authorizer = resourceManagerAuthorizer
	rdClient.AddToUserAgent(userAgent)

	p := &provider{
		settings: settings,

		appClient:    appClient,
		spClient:     &spClient,
		groupsClient: &groupsClient,
		raClient:     &raClient,
		rdClient:     &rdClient,
	}

	return p, nil
}

// getAuthorizer attempts to create an authorizer, preferring ClientID/Secret if present,
// and falling back to MSI if not.
func getAuthorizer(settings *clientSettings, resource string) (authorizer autorest.Authorizer, err error) {

	if settings.ClientID != "" && settings.ClientSecret != "" && settings.TenantID != "" {
		config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
		config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
		config.Resource = resource
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	} else {
		config := auth.NewMSIConfig()
		config.Resource = resource
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	}

	return authorizer, nil
}

// CreateApplication create a new Azure application object.
func (p *provider) CreateApplication(ctx context.Context, displayName string) (result api.ApplicationResult, err error) {
	return p.appClient.CreateApplication(ctx, displayName)
}

func (p *provider) GetApplication(ctx context.Context, applicationObjectID string) (result api.ApplicationResult, err error) {
	return p.appClient.GetApplication(ctx, applicationObjectID)
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (p *provider) DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error) {
	return p.appClient.DeleteApplication(ctx, applicationObjectID)
}

func (p *provider) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result api.PasswordCredentialResult, err error) {
	return p.appClient.AddApplicationPassword(ctx, applicationObjectID, displayName, endDateTime)
}

func (p *provider) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error) {
	return p.appClient.RemoveApplicationPassword(ctx, applicationObjectID, keyID)
}

// CreateServicePrincipal creates a new Azure service principal.
// An Application must be created prior to calling this and pass in parameters.
func (p *provider) CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	return p.spClient.Create(ctx, parameters)
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
func (p *provider) AddGroupMember(ctx context.Context, groupObjectID string, parameters graphrbac.GroupAddMemberParameters) (result autorest.Response, err error) {
	return p.groupsClient.AddMember(ctx, groupObjectID, parameters)
}

// RemoveGroupMember removes a member from a AAD Group.
func (p *provider) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (result autorest.Response, err error) {
	return p.groupsClient.RemoveMember(ctx, groupObjectID, memberObjectID)
}

// GetGroup gets group information from the directory.
func (p *provider) GetGroup(ctx context.Context, objectID string) (result graphrbac.ADGroup, err error) {
	return p.groupsClient.Get(ctx, objectID)
}

// ListGroups gets list of groups for the current tenant.
func (p *provider) ListGroups(ctx context.Context, filter string) (result []graphrbac.ADGroup, err error) {
	page, err := p.groupsClient.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}
