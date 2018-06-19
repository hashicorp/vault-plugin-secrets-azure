package azuresecrets

import (
	"errors"
	"os"

	"github.com/Azure/go-autorest/autorest/azure"
)

// azureSettings is used by a azureClient to connect to Azure. It is created
// from a combination of Vault config settings and environment variables.
type azureSettings struct {
	SubscriptionID string
	TenantID       string
	ClientID       string
	ClientSecret   string
	Environment    azure.Environment
	Resource       string
}

func getAzureSettings(config *azureConfig) (*azureSettings, error) {
	settings := new(azureSettings)

	envTenantID := os.Getenv("AZURE_TENANT_ID")
	switch {
	case envTenantID != "":
		settings.TenantID = envTenantID
	case config.TenantID != "":
		settings.TenantID = config.TenantID
	default:
		return nil, errors.New("tenant_id is required")
	}

	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		subscriptionID = config.SubscriptionID
	}
	settings.SubscriptionID = subscriptionID

	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		clientID = config.ClientID
	}
	settings.ClientID = clientID

	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = config.ClientSecret
	}
	settings.ClientSecret = clientSecret

	resource := os.Getenv("AZURE_AD_RESOURCE")
	if resource == "" {
		resource = config.Resource
	}
	settings.Resource = resource

	envName := os.Getenv("AZURE_ENVIRONMENT")
	if envName == "" {
		envName = config.Environment
	}
	if envName == "" {
		settings.Environment = azure.PublicCloud
	} else {
		var err error
		settings.Environment, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	return settings, nil
}
