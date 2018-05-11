package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure-Samples/azure-sdk-for-go-samples/helpers"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/davecgh/go-spew/spew"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
)

const (
	passwordLength = 30
	maxRetries     = 36

	principalNotFoundErr = "PrincipalNotFound"
)

//type azureSettings struct {
//	TenantID     string
//	ClientID     string
//	ClientSecret string
//	Environment  azure.Environment
//	Resource     string
//}

//func getAzureSettings(config *azureConfig) (*azureSettings, error) {
//	settings := new(azureSettings)
//
//	envTenantID := os.Getenv("AZURE_TENANT_ID")
//	switch {
//	case envTenantID != "":
//		settings.TenantID = envTenantID
//	case config.TenantID != "":
//		settings.TenantID = config.TenantID
//	default:
//		return nil, errors.New("tenant_id is required")
//	}
//
//	//envResource := os.Getenv("AZURE_AD_RESOURCE")
//	//switch {
//	//case envResource != "":
//	//	settings.Resource = envResource
//	//case config.Resource != "":
//	//	settings.Resource = config.Resource
//	//default:
//	//	return nil, errors.New("resource is required")
//	//}
//
//	clientID := os.Getenv("AZURE_CLIENT_ID")
//	if clientID == "" {
//		clientID = config.ClientID
//	}
//	settings.ClientID = clientID
//
//	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
//	if clientSecret == "" {
//		clientSecret = config.ClientSecret
//	}
//	settings.ClientSecret = clientSecret
//
//	envName := os.Getenv("AZURE_ENVIRONMENT")
//	if envName == "" {
//		envName = config.Environment
//	}
//	if envName == "" {
//		settings.Environment = azure.PublicCloud
//	} else {
//		var err error
//		settings.Environment, err = azure.EnvironmentFromName(envName)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	return settings, nil
//}

func validateIdentity(identity string) error {
	// check format and perhaps whether it exists?
	return nil
}

func (b *azureSecretBackend) addMachineIdentities(ctx context.Context, resourceGroup, vm string, identities []string) error {
	for _, identity := range identities {
		if err := validateIdentity(identity); err != nil {
			return err
		}
	}

	vmClient := compute.NewVirtualMachinesClient(helpers.SubscriptionID())

	settings, err := getAzureSettings(&azureConfig{})
	if err != nil {
		return err
	}

	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err := config.Authorizer()
	if err != nil {
		return err
	}

	vmClient.Authorizer = authorizer
	vmClient.AddToUserAgent(helpers.UserAgent())

	existingVM, err := vmClient.Get(ctx, resourceGroup, vm, "")
	if err != nil {
		return err
	}

	existingIdentities := *existingVM.Identity.IdentityIds
	existingIdentities = append(existingIdentities, identities...)
	existingIdentities = strutil.RemoveDuplicates(existingIdentities, false)

	return b.updateMachineIdentities(ctx, resourceGroup, vm, existingIdentities)
}

func (b *azureSecretBackend) removeMachineIdentities(ctx context.Context, resourceGroup, vm string, identities []string) error {
	for _, identity := range identities {
		if err := validateIdentity(identity); err != nil {
			return err
		}
	}

	vmClient := compute.NewVirtualMachinesClient(helpers.SubscriptionID())

	settings, err := getAzureSettings(&azureConfig{})
	if err != nil {
		return err
	}

	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err := config.Authorizer()
	if err != nil {
		return err
	}

	vmClient.Authorizer = authorizer
	vmClient.AddToUserAgent(helpers.UserAgent())

	existingVm, err := vmClient.Get(ctx, resourceGroup, vm, "")
	if err != nil {
		return err
	}

	existingIdentities := *existingVm.Identity.IdentityIds
	for _, i := range identities {
		existingIdentities = strutil.StrListDelete(existingIdentities, i)
	}

	return b.updateMachineIdentities(ctx, resourceGroup, vm, existingIdentities)
}

func (b *azureSecretBackend) updateMachineIdentities(ctx context.Context, resourceGroup, vm string, identities []string) error {
	for _, identity := range identities {
		if err := validateIdentity(identity); err != nil {
			return err
		}
	}

	vmClient := compute.NewVirtualMachinesClient(helpers.SubscriptionID())

	settings, err := getAzureSettings(&azureConfig{})
	if err != nil {
		return err
	}

	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err := config.Authorizer()
	if err != nil {
		return err
	}

	vmClient.Authorizer = authorizer
	vmClient.AddToUserAgent(helpers.UserAgent())

	_, err = vmClient.Update(context.Background(), resourceGroup, vm, compute.VirtualMachineUpdate{
		Identity: &compute.VirtualMachineIdentity{
			Type:        compute.ResourceIdentityTypeSystemAssignedUserAssigned,
			IdentityIds: &identities,
		},
	})

	return err
}

type azureClient struct {
	settings *azureSettings
}

func newAzureClient() (*azureClient, error) {
	settings, err := getAzureSettings(&azureConfig{})

	if err != nil {
		return nil, err
	}

	c := azureClient{
		settings: settings,
	}

	return &c, nil
}

// Get current identities, add/remove ours, save the result
func updateIdentities() {
	vmClient := compute.NewVirtualMachinesClient(helpers.SubscriptionID())

	settings, err := getAzureSettings(&azureConfig{})
	if err != nil {
		fmt.Println(err)
	}
	spew.Dump(settings)

	config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
	config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
	config.Resource = settings.Environment.ResourceManagerEndpoint
	authorizer, err := config.Authorizer()
	if err != nil {
		fmt.Println(err)
	}

	vmClient.Authorizer = authorizer
	vmClient.AddToUserAgent(helpers.UserAgent())

	_, err = vmClient.Update(context.Background(), "msi_test_central", "identity-test-vm5", compute.VirtualMachineUpdate{
		Identity: &compute.VirtualMachineIdentity{
			Type:        compute.ResourceIdentityTypeSystemAssignedUserAssigned,
			IdentityIds: &[]string{},
		},
	})
	fmt.Println(err)
}

func generateCredential() {
}

// createApp creates a new Azure "Application". An Application is a needed to create service
// principles in subsequent for authentication
func (c *azureClient) createApp() (app *graphrbac.Application, err error) {
	config := auth.NewClientCredentialsConfig(c.settings.ClientID, c.settings.ClientSecret, c.settings.TenantID)
	config.AADEndpoint = c.settings.Environment.ActiveDirectoryEndpoint
	config.Resource = c.settings.Environment.GraphEndpoint
	authorizer, err := config.Authorizer()

	if err != nil {
		return nil, err
	}

	appClient := graphrbac.NewApplicationsClient(c.settings.TenantID)
	appClient.Authorizer = authorizer
	appClient.AddToUserAgent(helpers.UserAgent())

	// Generate a random app name
	name, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s", name)

	result, err := appClient.Create(context.Background(), graphrbac.ApplicationCreateParameters{
		AvailableToOtherTenants: to.BoolPtr(false),
		DisplayName:             to.StringPtr(name),
		Homepage:                to.StringPtr(url),
		IdentifierUris:          &[]string{url},
	})

	return &result, nil
}

// createSP creates a new service principal
func (c *azureClient) createSP(app *graphrbac.Application, duration time.Duration) (sp *graphrbac.ServicePrincipal, password string, err error) {
	config := auth.NewClientCredentialsConfig(c.settings.ClientID, c.settings.ClientSecret, c.settings.TenantID)
	config.AADEndpoint = c.settings.Environment.ActiveDirectoryEndpoint
	config.Resource = c.settings.Environment.GraphEndpoint
	authorizer, err := config.Authorizer()

	if err != nil {
		return nil, "", err
	}

	client := graphrbac.NewServicePrincipalsClient(c.settings.TenantID)
	client.Authorizer = authorizer
	client.AddToUserAgent(helpers.UserAgent())

	// Generate a random key id (which must be a UUID) and password
	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, "", err
	}

	password, err = credsutil.RandomAlphaNumeric(passwordLength, false)
	if err != nil {
		return nil, "", err
	}

	result, err := client.Create(context.Background(), graphrbac.ServicePrincipalCreateParameters{
		AppID:          app.AppID,
		AccountEnabled: to.BoolPtr(true),
		PasswordCredentials: &[]graphrbac.PasswordCredential{
			graphrbac.PasswordCredential{
				StartDate: &date.Time{time.Now()},
				EndDate:   &date.Time{time.Now().Add(time.Hour)},
				KeyID:     to.StringPtr(keyID), // NOTE: this has to be a guid, apparently
				Value:     to.StringPtr(password),
			},
		},
	})

	return &result, password, nil
}

// deleteApp deletes an Azure application
func (c *azureClient) deleteApp(appObjectID string) error {
	config := auth.NewClientCredentialsConfig(c.settings.ClientID, c.settings.ClientSecret, c.settings.TenantID)
	config.AADEndpoint = c.settings.Environment.ActiveDirectoryEndpoint
	config.Resource = c.settings.Environment.GraphEndpoint
	authorizer, err := config.Authorizer()

	if err != nil {
		return err
	}

	client := graphrbac.NewApplicationsClient(c.settings.TenantID)
	client.Authorizer = authorizer
	client.AddToUserAgent(helpers.UserAgent())

	resp, err := client.Delete(context.Background(), appObjectID)

	// Don't consider it and error if the object wasn't present
	if err != nil && resp.StatusCode == 404 {
		return nil
	}

	return err
}

// assignRoles assigns roles
func (c *azureClient) assignRoles(sp *graphrbac.ServicePrincipal, roles []azureRole) error {
	config := auth.NewClientCredentialsConfig(c.settings.ClientID, c.settings.ClientSecret, c.settings.TenantID)
	config.AADEndpoint = c.settings.Environment.ActiveDirectoryEndpoint
	config.Resource = c.settings.Environment.ResourceManagerEndpoint
	authorizer, err := config.Authorizer()

	if err != nil {
		return err
	}

	for _, role := range roles {
		// Generate an assignment ID
		assignmentID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}

		tries := 1
		for ; tries < maxRetries; tries++ {
			client := authorization.NewRoleAssignmentsClient(c.settings.SubscriptionID)
			client.Authorizer = authorizer
			client.AddToUserAgent(helpers.UserAgent())

			_, err := client.Create(context.Background(), role.Scope, assignmentID, authorization.RoleAssignmentCreateParameters{
				RoleAssignmentProperties: &authorization.RoleAssignmentProperties{
					RoleDefinitionID: to.StringPtr(role.RoleID),
					PrincipalID:      sp.ObjectID,
				},
			})

			if err == nil {
				break
			}

			if !strings.Contains(err.Error(), principalNotFoundErr) {
				return err
			}
			time.Sleep(5 * time.Second)
		}
		if tries >= maxRetries {
			return errors.New("unable to assign role")
		}
	}

	//	return &result, nil
	return nil
}
