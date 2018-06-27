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
	multierror "github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
)

const (
	passwordLength = 30
)

// azureClient offers higher level Azure operations that provide a simpler interface
// for handlers. It in turn relies on a Provider interface to access the lower level
// Azure Client SDK methods.
type azureClient struct {
	provider Provider
	settings *azureSettings
}

// newAzureClient create an azureClient using the given config.
// If the config is invalid or authentication fails, an error is returned.
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
		settings: settings,
	}

	return &c, nil
}

// createApp creates a new Azure application.
// An Application is a needed to create service principals used by
// the caller for authentication.
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

// createSP creates a new service principal.
func (c *azureClient) createSP(
	ctx context.Context,
	app *graphrbac.Application,
	duration time.Duration) (sp *graphrbac.ServicePrincipal, password string, err error) {

	// Generate a random key (which must be a UUID) and password
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
				EndDate:   &date.Time{time.Now().Add(duration)},
				KeyID:     to.StringPtr(keyID),
				Value:     to.StringPtr(password),
			},
		},
	})

	return &result, password, err
}

// deleteApp deletes an Azure application.
func (c *azureClient) deleteApp(ctx context.Context, appObjectID string) error {
	resp, err := c.provider.DeleteApplication(ctx, appObjectID)

	// Don't consider it an error if the object wasn't present
	if err != nil && resp.StatusCode == 404 {
		return nil
	}

	return err
}

// assignRoles assigns Azure roles to a service principal.
func (c *azureClient) assignRoles(ctx context.Context, sp *graphrbac.ServicePrincipal, roles []*azureRole) ([]string, error) {
	var retryCfg = retryConfig{
		Base:    2 * time.Second,
		Timeout: 3 * time.Minute,
		Ramp:    1.15,
	}

	var ids []string

	for _, role := range roles {
		assignmentID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}

		// retries are essential for this operation as there can be a significant deley between
		// when a service principal is created and when it is visible for other operations. If
		// it isn't visible yet, "PrincipalNotFound" is the error received and is not treated
		// as an error here.
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

			if !strings.Contains(err.Error(), "PrincipalNotFound") {
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

// unassignRoles deletes role assignments, if they existed.
// This is a clean-up operation that isn't essential to revocation. As such, an
// attempt is made to remove all assignments, and not return immediately if there
// is an error.
func (c *azureClient) unassignRoles(ctx context.Context, roleIDs []string) error {
	var merr *multierror.Error

	for _, id := range roleIDs {
		if _, err := c.provider.DeleteRoleAssignmentByID(ctx, id); err != nil {
			merr = multierror.Append(merr, errwrap.Wrapf("error unassigning role: {{err}}", err))
		}
	}

	return merr.ErrorOrNil()
}

// lookupRole attempts to find a role definition by ID (if provided) or by name.
// Role IDs are unique, but names are not. A slice is always returned and it is up
// to the caller to handle this variability in response count (0, 1, >1).
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

// azureSettings is used by a azureClient to configuret the client connectons to Azure.
// It is created from a combination of Vault config settings and environment variables.
type azureSettings struct {
	SubscriptionID string
	TenantID       string
	ClientID       string
	ClientSecret   string
	Environment    azure.Environment
}

// getAzureSettings creates a new azureSettings object.
// Environment variables have higher precedence than stored configuration.
func getAzureSettings(config *azureConfig) (*azureSettings, error) {
	firstAvailable := func(opts ...string) string {
		for _, s := range opts {
			if s != "" {
				return s
			}
		}
		return ""
	}

	var merr *multierror.Error

	settings := new(azureSettings)

	settings.ClientID = firstAvailable(os.Getenv("AZURE_CLIENT_ID"), config.ClientID)
	settings.ClientSecret = firstAvailable(os.Getenv("AZURE_CLIENT_SECRET"), config.ClientSecret)
	if settings.SubscriptionID = firstAvailable(os.Getenv("AZURE_SUBSCRIPTION_ID"), config.SubscriptionID); settings.SubscriptionID == "" {
		merr = multierror.Append(merr, errors.New("subscription_id is required"))
	}

	settings.TenantID = firstAvailable(os.Getenv("AZURE_TENANT_ID"), config.TenantID)
	if settings.TenantID == "" {
		merr = multierror.Append(merr, errors.New("tenant_id is required"))
	}

	envName := firstAvailable(os.Getenv("AZURE_ENVIRONMENT"), config.Environment, "AZUREPUBLICCLOUD")
	env, err := azure.EnvironmentFromName(envName)
	if err != nil {
		merr = multierror.Append(merr, err)
	}
	settings.Environment = env

	return settings, merr.ErrorOrNil()
}

// retryConfig configures the behavior of retry
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
