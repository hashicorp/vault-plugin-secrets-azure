package azuresecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
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

var retryConfig = RetryConfig{
	Base:    2 * time.Second,
	Timeout: 3 * time.Minute,
	Ramp:    1.15,
}

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
	var ids []string

	for _, role := range roles {
		// Generate an assignment ID
		assignmentID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}

		err = Retry(ctx, retryConfig, func() (bool, error) {
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
