package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/manicminer/hamilton/msgraph"
)

const (
	defaultLeaseTTLHr = 1 * time.Hour
	maxLeaseTTLHr     = 12 * time.Hour
	defaultTestTTL    = 300
	defaultTestMaxTTL = 3600
	passwordLength    = 12
)

func getTestBackend(t *testing.T, initConfig bool) (*azureSecretBackend, logical.Storage) {
	b := backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr,
			MaxLeaseTTLVal:     maxLeaseTTLHr,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.settings = new(clientSettings)
	mockProvider := newMockProvider()
	b.getProvider = func(s *clientSettings) (AzureProvider, error) {
		return mockProvider, nil
	}

	if initConfig {
		cfg := map[string]interface{}{
			"subscription_id": generateUUID(),
			"tenant_id":       generateUUID(),
			"client_id":       "testClientId",
			"client_secret":   "testClientSecret",
			"environment":     "AZURECHINACLOUD",
			"ttl":             defaultTestTTL,
			"max_ttl":         defaultTestMaxTTL,
		}

		testConfigCreate(t, b, config.StorageView, cfg)
	}

	return b, config.StorageView
}

// mockProvider is a Provider that provides stubs and simple, deterministic responses.
type mockProvider struct {
	subscriptionID            string
	applications              map[string]string
	passwords                 map[string]string
	servicePrincipals         map[string]string
	failNextCreateApplication bool
}

// errMockProvider simulates a normal provider which fails to associate a role,
// returning an error
type errMockProvider struct {
	*mockProvider
}

// CreateRoleAssignment for the errMockProvider intentionally fails
func (e *errMockProvider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return authorization.RoleAssignment{}, errors.New("PrincipalNotFound")
}

// GetApplication for the errMockProvider only returns an application if that
// key is found, unlike mockProvider which returns the same application object
// id each time. Existing tests depend on the mockProvider behavior, which is
// why errMockProvider has it's own version.
func (e *errMockProvider) GetApplication(ctx context.Context, applicationObjectID string) (*msgraph.Application, error) {
	appID, ok := e.applications[applicationObjectID]
	if ok {
		return &msgraph.Application{
			ID:    to.StringPtr(applicationObjectID),
			AppId: to.StringPtr(appID),
		}, nil
	}
	return &msgraph.Application{}, errors.New("not found")
}

func newErrMockProvider() AzureProvider {
	return &errMockProvider{
		mockProvider: &mockProvider{
			subscriptionID:    generateUUID(),
			applications:      make(map[string]string),
			passwords:         make(map[string]string),
			servicePrincipals: make(map[string]string),
		},
	}
}

func newMockProvider() AzureProvider {
	return &mockProvider{
		subscriptionID:    generateUUID(),
		applications:      make(map[string]string),
		passwords:         make(map[string]string),
		servicePrincipals: make(map[string]string),
	}
}

// ListRoles returns a single fake role based on the inbound filter
func (m *mockProvider) ListRoles(ctx context.Context, scope string, filter string) (result []authorization.RoleDefinition, err error) {
	reRoleName := regexp.MustCompile("roleName eq '(.*)'")

	match := reRoleName.FindAllStringSubmatch(filter, -1)
	if len(match) > 0 {
		name := match[0][1]
		if name == "multiple" {
			return []authorization.RoleDefinition{
				{
					ID: to.StringPtr(fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s-1", name)),
					RoleDefinitionProperties: &authorization.RoleDefinitionProperties{
						RoleName: to.StringPtr(name),
					},
				},
				{
					ID: to.StringPtr(fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s-2", name)),
					RoleDefinitionProperties: &authorization.RoleDefinitionProperties{
						RoleName: to.StringPtr(name),
					},
				},
			}, nil
		}
		return []authorization.RoleDefinition{
			{
				ID: to.StringPtr(fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s", name)),
				RoleDefinitionProperties: &authorization.RoleDefinitionProperties{
					RoleName: to.StringPtr(name),
				},
			},
		}, nil
	}

	return []authorization.RoleDefinition{}, nil
}

// GetRoleByID will returns a fake role definition from the povided ID
// Assumes an ID format of: .*FAKE_ROLE-{rolename}
func (m *mockProvider) GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error) {
	d := authorization.RoleDefinition{}
	s := strings.Split(roleID, "FAKE_ROLE-")
	if len(s) > 1 {
		d.ID = to.StringPtr(roleID)
		d.RoleDefinitionProperties = &authorization.RoleDefinitionProperties{
			RoleName: to.StringPtr(s[1]),
		}
	}

	return d, nil
}

func (m *mockProvider) CreateServicePrincipal(ctx context.Context, parameters msgraph.ServicePrincipal) (*msgraph.ServicePrincipal, error) {
	id := generateUUID()
	m.servicePrincipals[id] = *parameters.AppId
	return &msgraph.ServicePrincipal{
		ID:    to.StringPtr(id),
		AppId: parameters.AppId,
	}, nil
}

func (m *mockProvider) GetServicePrincipal(ctx context.Context, objectID string) (*msgraph.ServicePrincipal, error) {
	_, ok := m.servicePrincipals[objectID]
	if !ok {
		return nil, errors.New("not found")
	}
	return &msgraph.ServicePrincipal{
		ID: to.StringPtr(objectID),
	}, nil
}

func (m *mockProvider) DeleteServicePrincipal(ctx context.Context, objectID string) error {
	delete(m.servicePrincipals, objectID)
	return nil
}

func (m *mockProvider) CreateApplication(ctx context.Context, parameters msgraph.Application) (*msgraph.Application, error) {
	if m.failNextCreateApplication {
		m.failNextCreateApplication = false
		return &msgraph.Application{}, errors.New("Mock: fail to create application")
	}
	appObjID := generateUUID()
	appID := generateUUID()
	m.applications[appObjID] = appID

	return &msgraph.Application{
		ID:    to.StringPtr(appObjID),
		AppId: to.StringPtr(appID),
	}, nil
}

func (m *mockProvider) GetApplication(ctx context.Context, applicationObjectID string) (*msgraph.Application, error) {
	creds := make([]msgraph.PasswordCredential, 0)
	for keyId, i := range m.passwords {
		if i == applicationObjectID {
			creds = append(creds, msgraph.PasswordCredential{
				KeyId: to.StringPtr(keyId),
			})
		}
	}

	appID, ok := m.applications[applicationObjectID]
	if !ok {
		appID = generateUUID()
	}
	return &msgraph.Application{
		ID:                  to.StringPtr(applicationObjectID),
		AppId:               to.StringPtr(appID),
		PasswordCredentials: &creds,
	}, nil
}

func (m *mockProvider) DeleteApplication(ctx context.Context, applicationObjectID string) error {
	delete(m.applications, applicationObjectID)
	return nil
}

func (m *mockProvider) AddApplicationPassword(ctx context.Context, applicationObjectID string, credential msgraph.PasswordCredential) (newCredential *msgraph.PasswordCredential, err error) {
	keyId := generateUUID()
	m.passwords[keyId] = applicationObjectID
	return &msgraph.PasswordCredential{
		KeyId:      to.StringPtr(keyId),
		SecretText: to.StringPtr("p@ssw0rd!23$"),
	}, nil
}

func (m *mockProvider) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyId string) (err error) {
	delete(m.passwords, keyId)
	return nil
}

func (m *mockProvider) appExists(appObjID string) bool {
	_, ok := m.applications[appObjID]
	return ok
}

func (m *mockProvider) passwordExists(keyID string) bool {
	_, ok := m.passwords[keyID]
	return ok
}

func (m *mockProvider) VMGet(ctx context.Context, resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error) {
	return compute.VirtualMachine{}, nil
}

func (m *mockProvider) VMUpdate(ctx context.Context, resourceGroupName string, VMName string, parameters compute.VirtualMachineUpdate) (result compute.VirtualMachinesUpdateFuture, err error) {
	return compute.VirtualMachinesUpdateFuture{}, nil
}

func (m *mockProvider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return authorization.RoleAssignment{
		ID: to.StringPtr(generateUUID()),
	}, nil
}

func (m *mockProvider) DeleteRoleAssignmentByID(ctx context.Context, roleID string) (result authorization.RoleAssignment, err error) {
	return authorization.RoleAssignment{}, nil
}

// AddGroupMembers adds members to an AAD Group.
func (m *mockProvider) AddGroupMember(ctx context.Context, group *msgraph.Group) (err error) {
	return nil
}

// RemoveGroupMember removes a member from a AAD Group.
func (m *mockProvider) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (err error) {
	return nil
}

// GetGroup gets group information from the directory.
func (m *mockProvider) GetGroup(ctx context.Context, objectID string) (result *msgraph.Group, err error) {
	g := msgraph.Group{
		ID: to.StringPtr(objectID),
	}
	s := strings.Split(objectID, "FAKE_GROUP-")
	if len(s) > 1 {
		g.DisplayName = to.StringPtr(s[1])
	}

	return &g, nil
}

// ListGroups gets list of groups for the current tenant.
func (m *mockProvider) ListGroups(ctx context.Context, filter string) (result *[]msgraph.Group, err error) {
	reGroupName := regexp.MustCompile("displayName eq '(.*)'")

	match := reGroupName.FindAllStringSubmatch(filter, -1)
	if len(match) > 0 {
		name := match[0][1]
		if name == "multiple" {
			return &[]msgraph.Group{
				{
					ID:          to.StringPtr(fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s-1", name)),
					DisplayName: to.StringPtr(name),
				},
				{
					ID:          to.StringPtr(fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s-2", name)),
					DisplayName: to.StringPtr(name),
				},
			}, nil
		}

		return &[]msgraph.Group{
			{
				ID:          to.StringPtr(fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s", name)),
				DisplayName: to.StringPtr(name),
			},
		}, nil
	}

	return &[]msgraph.Group{}, nil
}
