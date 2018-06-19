package azuresecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Azure-Samples/azure-sdk-for-go-samples/helpers"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/helper/pluginutil"
	"golang.org/x/oauth2"
)

// Provider is an interface to access underlying Azure client objects. Where practical the
// underlying function signature is preserved. AzureClient provider higher level operations
// atop Provider.
type Provider interface {
	ApplicationsClient
	ServicePrincipalsClient
	VirtualMachinesClient
	RoleAssignmentsClient
	RoleDefinitionsClient
	TokenVerifier
}

type ApplicationsClient interface {
	CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error)
}

type ServicePrincipalsClient interface {
	CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error)
}

type VirtualMachinesClient interface {
	VMGet(ctx context.Context, resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (compute.VirtualMachine, error)
	VMUpdate(ctx context.Context, resourceGroupName string, VMName string, parameters compute.VirtualMachineUpdate) (compute.VirtualMachinesUpdateFuture, error)
}

type RoleAssignmentsClient interface {
	CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleID string) (authorization.RoleAssignment, error)
}

type RoleDefinitionsClient interface {
	ListRoles(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
	GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error)
}

type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (*oidc.IDToken, error)
}

// azureProvider is a concrete implementation of Provider. The goal is that in most cases it
// is a simple passthrough to the appropriate client object. But if the response requires minor
// processing this is more practical at this layer, the response may different from the Azure signature.
type azureProvider struct {
	settings *azureSettings

	appClient    *graphrbac.ApplicationsClient
	spClient     *graphrbac.ServicePrincipalsClient
	raClient     *authorization.RoleAssignmentsClient
	rdClient     *authorization.RoleDefinitionsClient
	vmClient     *compute.VirtualMachinesClient
	oidcVerifier *oidc.IDTokenVerifier
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

func (p *azureProvider) VerifyToken(ctx context.Context, token string) (*oidc.IDToken, error) {
	return p.oidcVerifier.Verify(ctx, token)
}

func (p *azureProvider) VMGet(ctx context.Context, resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error) {
	return p.vmClient.Get(ctx, resourceGroupName, VMName, expand)
}

func (p *azureProvider) VMUpdate(ctx context.Context, resourceGroupName string, VMName string, parameters compute.VirtualMachineUpdate) (result compute.VirtualMachinesUpdateFuture, err error) {
	return p.vmClient.Update(ctx, resourceGroupName, VMName, parameters)
}

func (p *azureProvider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return p.raClient.Create(ctx, scope, roleAssignmentName, parameters)
}

func (p *azureProvider) DeleteRoleAssignmentByID(ctx context.Context, roleID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.DeleteByID(ctx, roleID)
}

func (b *azureSecretBackend) getProvider(cfg *azureConfig) (Provider, error) {
	b.providerLock.Lock()
	defer b.providerLock.Unlock()

	if b.provider != nil {
		return b.provider, nil
	}

	settings, err := getAzureSettings(cfg)

	if err != nil {
		return nil, err
	}

	// clients using the Active Directory endpoint
	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.GraphEndpoint
	authorizer, err := config.Authorizer()

	appClient := graphrbac.NewApplicationsClient(settings.TenantID)
	appClient.Authorizer = authorizer
	appClient.AddToUserAgent(helpers.UserAgent())

	spClient := graphrbac.NewServicePrincipalsClient(settings.TenantID)
	spClient.Authorizer = authorizer
	spClient.AddToUserAgent(helpers.UserAgent())

	// clients using the Resource Manager endpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err = config.Authorizer()

	raClient := authorization.NewRoleAssignmentsClient(settings.SubscriptionID)
	raClient.Authorizer = authorizer
	raClient.AddToUserAgent(helpers.UserAgent())

	rdClient := authorization.NewRoleDefinitionsClient(settings.SubscriptionID)
	rdClient.Authorizer = authorizer
	rdClient.AddToUserAgent(helpers.UserAgent())

	vmClient := compute.NewVirtualMachinesClient(settings.SubscriptionID)
	vmClient.Authorizer = authorizer
	vmClient.AddToUserAgent(helpers.UserAgent())

	oidcVerifier, err := newVerifier(settings)

	// Ping the metadata service (if available)
	go pingMetadataService()

	p := &azureProvider{
		settings:     settings,
		appClient:    &appClient,
		spClient:     &spClient,
		raClient:     &raClient,
		rdClient:     &rdClient,
		vmClient:     &vmClient,
		oidcVerifier: oidcVerifier,
	}

	b.provider = p

	return p, nil
}

type oidcDiscoveryInfo struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

func newVerifier(settings *azureSettings) (*oidc.IDTokenVerifier, error) {
	httpClient := cleanhttp.DefaultClient()

	// In many OIDC providers, the discovery endpoint matches the issuer. For Azure AD, the discovery
	// endpoint is the AD endpoint which does not match the issuer defined in the discovery payload. This
	// makes a request to the discovery URL to determine the issuer and key set information to configure
	// the OIDC verifier
	discoveryURL := fmt.Sprintf("%s%s/.well-known/openid-configuration", settings.Environment.ActiveDirectoryEndpoint, settings.TenantID)
	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errwrap.Wrapf("unable to read response body: {{err}}", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	var discoveryInfo oidcDiscoveryInfo
	if err := json.Unmarshal(body, &discoveryInfo); err != nil {
		return nil, errwrap.Wrapf("unable to unmarshal discovery url: {{err}}", err)
	}

	// Create a remote key set from the discovery endpoint
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	remoteKeySet := oidc.NewRemoteKeySet(ctx, discoveryInfo.JWKSURL)

	verifierConfig := &oidc.Config{
		ClientID:             settings.Resource,
		SupportedSigningAlgs: []string{oidc.RS256},
	}
	oidcVerifier := oidc.NewVerifier(discoveryInfo.Issuer, remoteKeySet, verifierConfig)

	return oidcVerifier, nil
}

func (b *azureSecretBackend) reset() {
	b.providerLock.Lock()
	defer b.providerLock.Unlock()

	b.provider = nil
}

// This is simply to ping the Azure metadata service, if it is running
// in Azure
func pingMetadataService() {
	client := cleanhttp.DefaultClient()
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/instance", nil)
	req.Header.Add("Metadata", "True")
	req.Header.Set("User-Agent", userAgent())

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2017-04-02")
	req.URL.RawQuery = q.Encode()

	client.Do(req)
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
