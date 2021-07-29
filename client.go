package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	msGraphEnvironments "github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/msgraph"
)

const (
	appNamePrefix  = "vault-"
	retryTimeout   = 80 * time.Second
	clientLifetime = 30 * time.Minute
)

// client offers higher level Azure operations that provide a simpler interface
// for handlers. It in turn relies on a Provider interface to access the lower level
// Azure Client SDK methods.
type client struct {
	provider   AzureProvider
	settings   *clientSettings
	expiration time.Time
}

// Valid returns whether the client defined and not expired.
func (c *client) Valid() bool {
	return c != nil && time.Now().Before(c.expiration)
}

// createApplication creates a new Azure application.
// An Application is needed to create service principals used by
// the caller for authentication.
func (c *client) createApplication(ctx context.Context) (app *msgraph.Application, err error) {
	name, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	name = appNamePrefix + name

	result, err := c.provider.CreateApplication(ctx, msgraph.Application{
		DisplayName:    to.StringPtr(name),
		SignInAudience: to.StringPtr(msgraph.SignInAudienceAzureADMyOrg),
	})

	if err != nil {
		return nil, errwrap.Wrapf("error creating application: {{err}}", err)
	}
	if result == nil {
		return nil, fmt.Errorf("error creating application: nil object returned")
	}
	if result.ID == nil {
		return nil, fmt.Errorf("error creating application: object with nil ID returned")
	}

	return result, nil
}

// createServicePrincipal creates a new service principal.
func (c *client) createServicePrincipal(ctx context.Context, applicationID string) (svcPrinc *msgraph.ServicePrincipal, err error) {

	result, err := c.provider.CreateServicePrincipal(ctx, msgraph.ServicePrincipal{
		AppId:          to.StringPtr(applicationID),
		AccountEnabled: to.BoolPtr(true),
	})

	if err != nil {
		return nil, errwrap.Wrapf("error creating service principal: {{err}}", err)
	}
	if result == nil {
		return nil, fmt.Errorf("error creating service principal: nil object returned")
	}
	if result.ID == nil {
		return nil, fmt.Errorf("error creating service principal: object with nil ID returned")
	}

	return result, nil
}

// addAppPassword adds a new password to an App's credentials list.
func (c *client) addAppPassword(ctx context.Context, appObjID string, duration time.Duration) (keyID string, password string, err error) {
	now := time.Now().UTC()
	expiry := now.Add(duration)
	cred := msgraph.PasswordCredential{
		StartDateTime: &now,
		EndDateTime:   &expiry,
	}

	newCred, err := c.provider.AddApplicationPassword(ctx, appObjID, cred)
	if err != nil {
		if strings.Contains(err.Error(), "size of the object has exceeded its limit") {
			err = errors.New("maximum number of Application passwords reached")
		}
		return "", "", errwrap.Wrapf("error updating credentials: {{err}}", err)
	}

	if newCred.KeyId == nil {
		return "", "", errors.New("keyId for returned credential was nil")
	}
	keyID = *newCred.KeyId

	if newCred.SecretText == nil {
		return "", "", errors.New("secretText for returned credential was nil")
	}
	password = *newCred.SecretText

	return keyID, password, nil
}

// deleteAppPassword removes a password, if present, from an App's credentials list.
func (c *client) deleteAppPassword(ctx context.Context, appObjID, keyID string) error {
	// Retrieve application
	app, err := c.provider.GetApplication(ctx, appObjID)
	if err != nil {
		return errwrap.Wrapf("error retrieving application: {{err}}", err)
	}

	// Remove credential
	found := false
	if app.PasswordCredentials != nil {
		for _, cred := range *app.PasswordCredentials {
			if strings.EqualFold(to.String(cred.KeyId), keyID) {
				found = true
				break
			}
		}
	}

	// Could not locate existing secret, so nothing to do
	if !found {
		return nil
	}

	// Remove the password
	if err := c.provider.RemoveApplicationPassword(ctx, appObjID, keyID); err != nil {
		return errwrap.Wrapf("error removing application password: {{err}}", err)
	}

	return nil
}

// deleteApplication deletes an Azure application.
func (c *client) deleteApplication(ctx context.Context, appObjectID string) error {
	return c.provider.DeleteApplication(ctx, appObjectID)
}

// deleteServicePrincipal deletes an Azure service principal
func (c *client) deleteServicePrincipal(ctx context.Context, objectID string) error {
	return c.provider.DeleteServicePrincipal(ctx, objectID)
}

// assignRoles assigns Azure roles to a service principal.
func (c *client) assignRoles(ctx context.Context, sp *msgraph.ServicePrincipal, roles []*AzureRole) ([]string, error) {
	var ids []string

	for _, role := range roles {
		assignmentID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}

		resultRaw, err := retry(ctx, func() (interface{}, bool, error) {
			ra, err := c.provider.CreateRoleAssignment(ctx, role.Scope, assignmentID,
				authorization.RoleAssignmentCreateParameters{
					RoleAssignmentProperties: &authorization.RoleAssignmentProperties{
						RoleDefinitionID: to.StringPtr(role.RoleID),
						PrincipalID:      sp.ID,
					},
				})

			// Propagation delays within Azure can cause this error occasionally, so don't quit on it.
			if err != nil && strings.Contains(err.Error(), "PrincipalNotFound") {
				return nil, false, nil
			}

			return to.String(ra.ID), true, err
		})

		if err != nil {
			return nil, errwrap.Wrapf("error while assigning roles: {{err}}", err)
		}

		ids = append(ids, resultRaw.(string))
	}

	return ids, nil
}

// unassignRoles deletes role assignments, if they existed.
// This is a clean-up operation that isn't essential to revocation. As such, an
// attempt is made to remove all assignments, and not return immediately if there
// is an error.
func (c *client) unassignRoles(ctx context.Context, roleIDs []string) error {
	var merr *multierror.Error

	for _, id := range roleIDs {
		if _, err := c.provider.DeleteRoleAssignmentByID(ctx, id); err != nil {
			merr = multierror.Append(merr, errwrap.Wrapf("error unassigning role: {{err}}", err))
		}
	}

	return merr.ErrorOrNil()
}

// addGroupMemberships adds the service principal to the Azure groups.
func (c *client) addGroupMemberships(ctx context.Context, sp *msgraph.ServicePrincipal, groups []*AzureGroup) error {
	if sp == nil {
		return errors.New("service principal was nil")
	}
	if sp.ID == nil {
		return errors.New("service principal object ID was nil")
	}
	for _, group := range groups {
		groupModel := msgraph.Group{ID: to.StringPtr(group.ObjectID)}
		groupModel.AppendMember(c.settings.MsGraphEnvironment.MsGraph.Endpoint, msgraph.Version10, *sp.ID)
		_, err := retry(ctx, func() (interface{}, bool, error) {
			err := c.provider.AddGroupMember(ctx, &groupModel)
			return nil, true, err
		})

		if err != nil {
			return errwrap.Wrapf("error while adding group membership: {{err}}", err)
		}
	}

	return nil
}

// removeGroupMemberships removes the passed service principal from the passed
// groups. This is a clean-up operation that isn't essential to revocation. As
// such, an attempt is made to remove all memberships, and not return
// immediately if there is an error.
func (c *client) removeGroupMemberships(ctx context.Context, servicePrincipalObjectID string, groupIDs []string) error {
	var merr *multierror.Error

	for _, id := range groupIDs {
		if err := c.provider.RemoveGroupMember(ctx, servicePrincipalObjectID, id); err != nil {
			merr = multierror.Append(merr, errwrap.Wrapf("error removing group membership: {{err}}", err))
		}
	}

	return merr.ErrorOrNil()
}

// groupObjectIDs is a helper for converting a list of AzureGroup
// objects to a list of their object IDs.
func groupObjectIDs(groups []*AzureGroup) []string {
	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		groupIDs = append(groupIDs, group.ObjectID)

	}
	return groupIDs
}

// search for roles by name
func (c *client) findRoles(ctx context.Context, roleName string) ([]authorization.RoleDefinition, error) {
	return c.provider.ListRoles(ctx, fmt.Sprintf("subscriptions/%s", c.settings.SubscriptionID), fmt.Sprintf("roleName eq '%s'", roleName))
}

// findGroups is used to find a group by name. It returns all groups matching
// the passsed name.
func (c *client) findGroups(ctx context.Context, groupName string) (*[]msgraph.Group, error) {
	return c.provider.ListGroups(ctx, fmt.Sprintf("displayName eq '%s'", groupName))
}

// clientSettings is used by a client to configure the connections to Azure.
// It is created from a combination of Vault config settings and environment variables.
type clientSettings struct {
	SubscriptionID     string
	TenantID           string
	ClientID           string
	ClientSecret       string
	Environment        azure.Environment
	MsGraphEnvironment msGraphEnvironments.Environment
	PluginEnv          *logical.PluginEnvironment
}

// getClientSettings creates a new clientSettings object.
// Environment variables have higher precedence than stored configuration.
func (b *azureSecretBackend) getClientSettings(ctx context.Context, config *azureConfig) (*clientSettings, error) {
	firstAvailable := func(opts ...string) string {
		for _, s := range opts {
			if s != "" {
				return s
			}
		}
		return ""
	}

	settings := new(clientSettings)

	settings.ClientID = firstAvailable(os.Getenv("AZURE_CLIENT_ID"), config.ClientID)
	settings.ClientSecret = firstAvailable(os.Getenv("AZURE_CLIENT_SECRET"), config.ClientSecret)

	settings.SubscriptionID = firstAvailable(os.Getenv("AZURE_SUBSCRIPTION_ID"), config.SubscriptionID)
	if settings.SubscriptionID == "" {
		return nil, errors.New("subscription_id is required")
	}

	settings.TenantID = firstAvailable(os.Getenv("AZURE_TENANT_ID"), config.TenantID)
	if settings.TenantID == "" {
		return nil, errors.New("tenant_id is required")
	}

	envName := firstAvailable(os.Getenv("AZURE_ENVIRONMENT"), config.Environment, "AZUREPUBLICCLOUD")
	env, err := azure.EnvironmentFromName(envName)
	if err != nil {
		return nil, err
	}
	settings.Environment = env

	// build clients that use Microsoft Graph
	envMapping := map[string]msGraphEnvironments.Environment{
		"AzureChinaCloud":        msGraphEnvironments.China,
		"AzureGermanCloud":       msGraphEnvironments.Germany,
		"AzurePublicCloud":       msGraphEnvironments.Global,
		"AzureUSGovernmentCloud": msGraphEnvironments.USGovernmentL4,
	}

	msGraphEnv, ok := envMapping[settings.Environment.Name]
	if !ok {
		return nil, fmt.Errorf("could not determine MS Graph environment from: %q", settings.Environment.Name)
	}
	settings.MsGraphEnvironment = msGraphEnv

	pluginEnv, err := b.System().PluginEnv(ctx)
	if err != nil {
		return nil, errwrap.Wrapf("error loading plugin environment: {{err}}", err)
	}
	settings.PluginEnv = pluginEnv

	return settings, nil
}

// retry will repeatedly call f until one of:
//
//   * f returns true
//   * the context is cancelled
//   * 80 seconds elapses. Vault's default request timeout is 90s; we want to expire before then.
//
// Delays are random but will average 5 seconds.
func retry(ctx context.Context, f func() (interface{}, bool, error)) (interface{}, error) {
	delayTimer := time.NewTimer(0)
	if _, hasTimeout := ctx.Deadline(); !hasTimeout {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, retryTimeout)
		defer cancel()
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		if result, done, err := f(); done {
			return result, err
		}

		delay := time.Duration(2000+rng.Intn(6000)) * time.Millisecond
		delayTimer.Reset(delay)

		select {
		case <-delayTimer.C:
			// Retry loop
		case <-ctx.Done():
			return nil, fmt.Errorf("retry failed: %w", ctx.Err())
		}
	}
}
