package azuresecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"subscription_id": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The tenant id for the Azure Active Directory.  This is sometimes
				referred to as Directory ID in AD.  This value can also be provided with the 
				AZURE_TENANT_ID environment variable.`,
			},
			"tenant_id": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The tenant id for the Azure Active Directory.  This is sometimes
				referred to as Directory ID in AD.  This value can also be provided with the 
				AZURE_TENANT_ID environment variable.`,
			},
			//"resource": &framework.FieldSchema{
			//	Type: framework.TypeString,
			//	Description: `The resource URL for the vault application in Azure Active Directory.
			//	This value can also be provided with the AZURE_AD_RESOURCE environment variable.`,
			//},
			"environment": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The Azure environment name. If not provided, AzurePublicCloud is used.
				This value can also be provided with the AZURE_ENVIRONMENT environment variable.`,
			},
			"client_id": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The OAuth2 client id to connection to Azure.
				This value can also be provided with the AZURE_CLIENT_ID environment variable.`,
			},
			"client_secret": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The OAuth2 client secret to connection to Azure.
				This value can also be provided with the AZURE_CLIENT_SECRET environment variable.`,
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
			logical.ReadOperation:   b.pathConfigRead,
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

type azureConfig struct {
	SubscriptionID string        `json:"subscription_id"`
	TenantID       string        `json:"tenant_id"`
	Resource       string        `json:"resource"` // TODO is this needed?
	Environment    string        `json:"environment"`
	ClientID       string        `json:"client_id"`
	ClientSecret   string        `json:"client_secret"`
	IdentityID     string        `json:"identity_id"`
	DefaultTTL     time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
}

func (b *azureSecretBackend) config(ctx context.Context, s logical.Storage) (*azureConfig, error) {
	config := new(azureConfig)
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return config, nil
	}

	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *azureSecretBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *azureSecretBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(azureConfig)
	}

	subscriptionID, ok := data.GetOk("subscription_id")
	if ok {
		config.SubscriptionID = subscriptionID.(string)
	}

	tenantID, ok := data.GetOk("tenant_id")
	if ok {
		config.TenantID = tenantID.(string)
	}

	resource, ok := data.GetOk("resource")
	if ok {
		config.Resource = resource.(string)
	}

	environment, ok := data.GetOk("environment")
	if ok {
		config.Environment = environment.(string)
	}

	clientID, ok := data.GetOk("client_id")
	if ok {
		config.ClientID = clientID.(string)
	}

	clientSecret, ok := data.GetOk("client_secret")
	if ok {
		config.ClientSecret = clientSecret.(string)
	}

	// Update token TTL.
	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		config.DefaultTTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	// Update token Max TTL.
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if ok {
		config.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	// Create a settings object to validate all required settings
	// are available
	if _, err := getAzureSettings(config); err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset backend
	//b.reset()

	return nil, nil
}

func (b *azureSecretBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"subscription_id": config.SubscriptionID,
			"tenant_id":       config.TenantID,
			"resource":        config.Resource,
			"environment":     config.Environment,
			"client_id":       config.ClientID,
			"identity_id":     config.IdentityID,
			"ttl":             int64(config.DefaultTTL / time.Second),
			"max_ttl":         int64(config.MaxTTL / time.Second),
		},
	}
	return resp, nil
}

const confHelpSyn = `Configures the Azure authentication backend.`
const confHelpDesc = `
The Azure authentication backend validates the login JWTs using the
configured credentials.  In order to validate machine information, the
OAuth2 client id and secret are used to query the Azure API.  The OAuth2
credentials require Microsoft.Compute/virtualMachines/read permission on
the resource requesting credentials.
`
