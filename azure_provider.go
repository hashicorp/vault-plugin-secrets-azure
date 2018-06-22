package azuresecrets

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/vault/helper/pluginutil"
)

// azureProvider is a concrete implementation of Provider. In most cases it is a simple passthrough
// to the appropriate client object. But if the response requires processing that is more practical
// at this layer, the response signature may different from the Azure signature.
type azureProvider struct {
	settings *azureSettings

	appClient *graphrbac.ApplicationsClient
	spClient  *graphrbac.ServicePrincipalsClient
	raClient  *authorization.RoleAssignmentsClient
	rdClient  *authorization.RoleDefinitionsClient

	// internal data to facilitate testing
	_spObjId string
}

// NewAzureProvider creates an azureProvider, backed by Azure client objects for underlying services.
func NewAzureProvider(settings *azureSettings) (Provider, error) {

	// build clients that use the Active Directory endpoint
	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.GraphEndpoint
	authorizer, err := config.Authorizer()
	if err != nil {
		return nil, err
	}

	appClient := graphrbac.NewApplicationsClient(settings.TenantID)
	appClient.Authorizer = authorizer
	appClient.AddToUserAgent(userAgent())

	spClient := graphrbac.NewServicePrincipalsClient(settings.TenantID)
	spClient.Authorizer = authorizer
	spClient.AddToUserAgent(userAgent())

	// build clients that use the Resource Manager endpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err = config.Authorizer()
	if err != nil {
		return nil, err
	}

	raClient := authorization.NewRoleAssignmentsClient(settings.SubscriptionID)
	raClient.Authorizer = authorizer
	raClient.AddToUserAgent(userAgent())

	rdClient := authorization.NewRoleDefinitionsClient(settings.SubscriptionID)
	rdClient.Authorizer = authorizer
	rdClient.AddToUserAgent(userAgent())

	p := &azureProvider{
		settings: settings,

		appClient: &appClient,
		spClient:  &spClient,
		raClient:  &raClient,
		rdClient:  &rdClient,
	}

	return p, nil
}

// CreateApplication create a new Azure application object.
func (p *azureProvider) CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error) {
	return p.appClient.Create(ctx, parameters)
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (p *azureProvider) DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error) {
	return p.appClient.Delete(ctx, applicationObjectID)
}

// CreateServicePrincipal creates a new Azure service principal.
// An Application must be created prior to calling this and pass in parameters.
func (p *azureProvider) CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	sp, err := p.spClient.Create(ctx, parameters)
	if sp.ObjectID != nil {
		p._spObjId = *sp.ObjectID
	}
	return sp, err
}

// ListRoles like all Azure roles with a scope (often subscription).
func (p *azureProvider) ListRoles(ctx context.Context, scope string, filter string) (result []authorization.RoleDefinition, err error) {
	page, err := p.rdClient.List(ctx, scope, filter)

	v := page.Values()

	if err != nil {
		return nil, err
	}

	return v, nil
}

// GetRoleByID fetches the full role definition given a roleID.
func (p *azureProvider) GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error) {
	return p.rdClient.GetByID(ctx, roleID)
}

// CreateRoleAssignment assigns a role to a service principal.
func (p *azureProvider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return p.raClient.Create(ctx, scope, roleAssignmentName, parameters)
}

// GetRoleAssignmentByID fetches the full role assignment info given a roleAssignmentID.
func (p *azureProvider) GetRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.GetByID(ctx, roleAssignmentID)
}

// DeleteRoleAssignmentByID deletes a role assignment.
func (p *azureProvider) DeleteRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.DeleteByID(ctx, roleAssignmentID)
}

// ListRoleAssignments lists all role assignments.
func (p *azureProvider) ListRoleAssignments(ctx context.Context, filter string) ([]authorization.RoleAssignment, error) {
	page, err := p.raClient.List(ctx, filter)

	// There is no need for paging; the caller only cares about the the first match and whether
	// there are 0, 1 or >1 items. Unpacking here is a simpler interface.
	v := page.Values()

	if err != nil {
		return nil, err
	}

	return v, nil
}

// userAgent determines the User Agent to send on HTTP requests.
func userAgent() string {
	version := os.Getenv(pluginutil.PluginVaultVersionEnv)
	projectURL := "https://www.vaultproject.io/"
	rt := runtime.Version()
	return fmt.Sprintf("Vault/%s (+%s; %s)", version, projectURL, rt)
}
