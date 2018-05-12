package azuresecrets

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Azure-Samples/azure-sdk-for-go-samples/helpers"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type azureSecretBackend struct {
	*framework.Backend

	l sync.RWMutex

	client   *azureClient
	provider Provider
}

type backend struct {
	*framework.Backend

	enabledIamResources iamutil.EnabledResources

	rolesetLock sync.Mutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *azureSecretBackend {
	var b = azureSecretBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: framework.PathAppend(
			pathsRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathSecretIdentity(&b),
				//	pathSecretAccessToken(&b),
				//	pathSecretServiceAccountKey(&b),
				pathCredential(&b),
			},
		),
		Secrets: []*framework.Secret{
			secretIdentity(&b),
			secretCredential(&b),
			//secretServiceAccountKey(&b),
		},

		BackendType:       logical.TypeLogical,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 1 * time.Minute, // TODO increase back to 5 minutes when done debugging
	}

	return &b
}

type prov struct {
	settings  *azureSettings
	appClient *graphrbac.ApplicationsClient
	spClient  *graphrbac.ServicePrincipalsClient
	raClient  *authorization.RoleAssignmentsClient
}

func (p *prov) getApplicationClient() ApplicationClient {
	return p.appClient
}

func (p *prov) getServicePrincipalClient() ServicePrincipalClient {
	return p.spClient
}

func (p *prov) getRoleAssignmentClient() RoleAssignmentClient {
	return p.raClient
}

func (b *azureSecretBackend) getProvider() (Provider, error) {
	if b.provider != nil {
		return b.provider, nil
	}

	settings, err := getAzureSettings(&azureConfig{})

	if err != nil {
		return nil, err
	}

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

	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err = config.Authorizer()
	raClient := authorization.NewRoleAssignmentsClient(settings.SubscriptionID)
	raClient.Authorizer = authorizer
	raClient.AddToUserAgent(helpers.UserAgent())

	p := &prov{
		settings:  settings,
		appClient: &appClient,
		spClient:  &spClient,
		raClient:  &raClient,
	}

	b.provider = p

	return p, nil
}

//func newHttpClient(ctx context.Context, s logical.Storage, scopes ...string) (*http.Client, error) {
//	if len(scopes) == 0 {
//		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
//	}
//
//	cfg, err := getConfig(ctx, s)
//	if err != nil {
//		return nil, err
//	}
//	credsJSON := ""
//	if cfg != nil {
//		credsJSON = cfg.CredentialsRaw
//	}
//
//	_, tokenSource, err := gcputil.FindCredentials(credsJSON, ctx, scopes...)
//	if err != nil {
//		return nil, err
//	}
//
//	tc := cleanhttp.DefaultClient()
//	return oauth2.NewClient(
//		context.WithValue(ctx, oauth2.HTTPClient, tc),
//		tokenSource), nil
//}

//func newIamAdmin(ctx context.Context, s logical.Storage) (*iam.Service, error) {
//	c, err := newHttpClient(ctx, s, iam.CloudPlatformScope)
//	if err != nil {
//		return nil, err
//	}
//
//	return iam.New(c)
//}

const backendHelp = `
The GCP secrets backend dynamically generates GCP IAM service
account keys with a given set of IAM policies. The service
account keys have a configurable lease set and are automatically
revoked at the end of the lease.

After mounting this backend, credentials to generate IAM keys must
be configured with the "config/" endpoints and policies must be
written using the "roles/" endpoints before any keys can be generated.
`
