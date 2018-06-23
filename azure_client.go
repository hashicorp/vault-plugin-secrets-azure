package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	multierror "github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
)

const (
	principalNotFoundErr = "PrincipalNotFound"
	passwordLength       = 30
)

// azureClient offers higher level Azure operations that provide a simpler interface
// for handlers. It in turn relies on a Provider interface to access the lower level
// Azure Client SDK methods.
type azureClient struct {
	provider Provider
	logger   log.Logger
	settings *azureSettings
}

func (b *azureSecretBackend) newAzureClient(ctx context.Context, cfg *azureConfig) (*azureClient, error) {
	settings, err := getAzureSettings(cfg)
	if err != nil {
		return nil, err
	}

	p, err := b.getProvider(settings)
	if err != nil {
		return nil, err
	}

	c := azureClient{
		provider: p,
		logger:   b.Logger(),
		settings: settings,
	}

	return &c, nil
}

// createApp creates a new Azure "Application". An Application is a needed to create service
// principles in subsequent for authentication
func (c *azureClient) createApp(ctx context.Context) (app *graphrbac.Application, err error) {
	name, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s", name)

	result, err := c.provider.CreateApplication(ctx, graphrbac.ApplicationCreateParameters{
		AvailableToOtherTenants: to.BoolPtr(false),
		DisplayName:             to.StringPtr(name),
		Homepage:                to.StringPtr(url),
		IdentifierUris:          &[]string{url},
	})

	return &result, err
}

// createSP creates a new service principal
func (c *azureClient) createSP(ctx context.Context, app *graphrbac.Application, duration time.Duration) (sp *graphrbac.ServicePrincipal, password string, err error) {

	// Generate a random key id (which must be a UUID) and password
	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, "", err
	}

	password, err = credsutil.RandomAlphaNumeric(passwordLength, false)
	if err != nil {
		return nil, "", err
	}

	result, err := c.provider.CreateServicePrincipal(ctx, graphrbac.ServicePrincipalCreateParameters{
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

	return &result, password, err
}

// deleteApp deletes an Azure application
func (c *azureClient) deleteApp(ctx context.Context, appObjectID string) error {
	resp, err := c.provider.DeleteApplication(ctx, appObjectID)

	// Don't consider it an error if the object wasn't present
	if err != nil && resp.StatusCode == 404 {
		return nil
	}

	return err
}

// assignRoles assigns roles to a service principal
func (c *azureClient) assignRoles(ctx context.Context, sp *graphrbac.ServicePrincipal, roles []*azureRole) ([]string, error) {
	var retryCfg = retryConfig{
		Base:    2 * time.Second,
		Timeout: 3 * time.Minute,
		Ramp:    1.15,
	}

	var ids []string

	for _, role := range roles {
		// Generate an assignment ID
		assignmentID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}

		err = retry(ctx, retryCfg, func() (bool, error) {
			ra, err := c.provider.CreateRoleAssignment(ctx, role.Scope, assignmentID,
				authorization.RoleAssignmentCreateParameters{
					RoleAssignmentProperties: &authorization.RoleAssignmentProperties{
						RoleDefinitionID: to.StringPtr(role.RoleID),
						PrincipalID:      sp.ObjectID,
					},
				})

			if err == nil {
				ids = append(ids, *ra.ID)
				return true, nil
			}

			if !strings.Contains(err.Error(), principalNotFoundErr) {
				return true, errwrap.Wrapf("error while assigning role: {{err}}", err)
			}

			return false, nil
		})

		if err != nil {
			return nil, err
		}
	}

	return ids, nil
}

// unassignRoles deletes role assignments, if they existed
// This is a clean-up operation, and well
func (c *azureClient) unassignRoles(ctx context.Context, roleIDs []string) error {
	var merr *multierror.Error

	for _, id := range roleIDs {
		if _, err := c.provider.DeleteRoleAssignmentByID(ctx, id); err != nil {
			merr = multierror.Append(merr, errwrap.Wrapf("error unassigning role: {{err}}", err))
		}
	}

	return merr.ErrorOrNil()
}

func (c *azureClient) lookupRole(ctx context.Context, roleName, roleId string) ([]authorization.RoleDefinition, error) {
	if roleId != "" {
		r, err := c.provider.GetRoleByID(ctx, roleId)
		if err != nil {
			return nil, err
		}
		if r.ID == nil {
			return nil, nil
		}
		return []authorization.RoleDefinition{r}, nil
	}
	return c.provider.ListRoles(ctx, fmt.Sprintf("subscriptions/%s", c.settings.SubscriptionID), fmt.Sprintf("roleName eq '%s'", roleName))
}

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

// getAzureSettings creates a new azureSettings object.
// Environment variables have higher precedence than stored configuration.
func getAzureSettings(config *azureConfig) (*azureSettings, error) {
	settings := new(azureSettings)

	settings.TenantID = firstSupplied(os.Getenv("AZURE_TENANT_ID"), config.TenantID)
	if settings.TenantID == "" {
		return nil, errors.New("tenant_id is required")
	}

	settings.SubscriptionID = firstSupplied(os.Getenv("AZURE_SUBSCRIPTION_ID"), config.SubscriptionID)
	settings.ClientID = firstSupplied(os.Getenv("AZURE_CLIENT_ID"), config.ClientID)
	settings.ClientSecret = firstSupplied(os.Getenv("AZURE_CLIENT_SECRET"), config.ClientSecret)
	settings.Resource = firstSupplied(os.Getenv("AZURE_AD_RESOURCE"), config.Resource)

	settings.Environment = azure.PublicCloud
	envName := firstSupplied(os.Getenv("AZURE_ENVIRONMENT"), config.Environment)
	if envName != "" {
		var err error
		settings.Environment, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	return settings, nil
}

// firstSupplied return the first option that is not an empty string
func firstSupplied(opts ...string) string {
	for _, s := range opts {
		if s != "" {
			return s
		}
	}
	return ""
}

type retryConfig struct {
	Base    time.Duration // start and minimum retry duration
	Timeout time.Duration // max total retry runtime. 0 == indefinite
	Ramp    float64       // rate of delay increase
	Jitter  bool          // randomize between [Base, delay)
}

// retry calls func f() at a cadence defined by cfg.
// Retries continue until f() returns true, Timeout has elapsed,
// or the context is cancelled.
func retry(ctx context.Context, cfg retryConfig, f func() (bool, error)) error {
	rand.Seed(time.Now().Unix())

	var endCh <-chan time.Time
	if cfg.Timeout != 0 {
		endCh = time.NewTimer(cfg.Timeout).C
	}

	for count := 0; ; count++ {
		if done, err := f(); done {
			return err
		}

		b := float64(cfg.Base)
		dur := int64(math.Max(b, b*math.Pow(cfg.Ramp, float64(count))))
		if cfg.Jitter {
			dur = rand.Int63n(dur)
		}
		delay := time.NewTimer(time.Duration(dur))

		select {
		case <-delay.C:
		case <-endCh:
			return errors.New("retry: timeout")
		case <-ctx.Done():
			return errors.New("retry: cancelled")
		}
	}
}
