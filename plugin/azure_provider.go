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

// azureProvider is a concrete implementation of Provider. The goal is that in most cases it
// is a simple passthrough to the appropriate client object. But if the response requires minor
// processing this is more practical at this layer, the response may different from the Azure signature.
type azureProvider struct {
	settings *azureSettings

	appClient *graphrbac.ApplicationsClient
	spClient  *graphrbac.ServicePrincipalsClient
	raClient  *authorization.RoleAssignmentsClient
	rdClient  *authorization.RoleDefinitionsClient
}

// NewAzureProvider creates an azureProvider
func NewAzureProvider(settings *azureSettings) (Provider, error) {

	// clients using the Active Directory endpoint
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

	// clients using the Resource Manager endpoint
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
		settings:  settings,
		appClient: &appClient,
		spClient:  &spClient,
		raClient:  &raClient,
		rdClient:  &rdClient,
	}

	return p, nil
}

func (p *azureProvider) ListRoles(ctx context.Context, scope string, filter string) (result []authorization.RoleDefinition, err error) {
	page, err := p.rdClient.List(ctx, scope, filter)

	v := page.Values()

	if err != nil {
		return nil, err
	}

	return v, nil
}

func (p *azureProvider) GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error) {
	return p.rdClient.GetByID(ctx, roleID)
}

func (p *azureProvider) CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	return p.spClient.Create(ctx, parameters)
}

func (p *azureProvider) CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error) {
	return p.appClient.Create(ctx, parameters)
}

func (p *azureProvider) DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error) {
	return p.appClient.Delete(ctx, applicationObjectID)
}

func (p *azureProvider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return p.raClient.Create(ctx, scope, roleAssignmentName, parameters)
}

func (p *azureProvider) DeleteRoleAssignmentByID(ctx context.Context, roleID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.DeleteByID(ctx, roleID)
}

// userAgent determines the User Agent to send on HTTP requests. This is mostly copied
// from the useragent helper in vault and may get replaced with something more general
// for plugins
func userAgent() string {
	version := os.Getenv(pluginutil.PluginVaultVersionEnv)
	projectURL := "https://www.vaultproject.io/"
	rt := runtime.Version()
	return fmt.Sprintf("Vault/%s (+%s; %s)", version, projectURL, rt)
}
