// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"

	"github.com/hashicorp/vault-plugin-secrets-azure/mocks"
)

// mockProvider is a Provider that provides stubs and simple, deterministic responses.
type mockProvider struct {
	applications              map[string]string
	servicePrincipals         map[string]bool
	deletedObjects            map[string]bool
	passwords                 map[string]string
	failNextCreateApplication bool
	lock                      sync.Mutex
}

func newMockProvider() AzureProvider {
	return &mockProvider{
		applications:      make(map[string]string),
		servicePrincipals: make(map[string]bool),
		deletedObjects:    make(map[string]bool),
		passwords:         make(map[string]string),
	}
}

// ListRoles returns a single fake role based on the inbound filter
func (m *mockProvider) ListRoleDefinitions(_ context.Context, _ string, filter string) ([]*armauthorization.RoleDefinition, error) {
	reRoleName := regexp.MustCompile("roleName eq '(.*)'")

	match := reRoleName.FindAllStringSubmatch(filter, -1)
	if len(match) > 0 {
		name := match[0][1]
		if name == "multiple" {
			id1 := fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s-1", name)
			id2 := fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s-2", name)
			return []*armauthorization.RoleDefinition{
				{
					ID: &id1,
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName: &name,
					},
					Name: &name,
				},
				{
					ID: &id2,
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName: &name,
					},
					Name: &name,
				},
			}, nil
		}
		id := fmt.Sprintf("/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-%s", name)
		return []*armauthorization.RoleDefinition{
			{
				ID: &id,
				Properties: &armauthorization.RoleDefinitionProperties{
					RoleName: &name,
				},
				Name: &name,
			},
		}, nil
	}

	return []*armauthorization.RoleDefinition{}, nil
}

func (m *mockProvider) ListRoleAssignments(_ context.Context, _ string) ([]*armauthorization.RoleAssignment, error) {
	return []*armauthorization.RoleAssignment{}, nil
}

// GetRoleByID will return a fake role definition from the provided ID
// Assumes an ID format of: .*FAKE_ROLE-{rolename}
func (m *mockProvider) GetRoleDefinitionByID(_ context.Context, roleID string) (armauthorization.RoleDefinitionsClientGetByIDResponse, error) {
	s := strings.Split(roleID, "FAKE_ROLE-")
	roleName := s[1]
	return armauthorization.RoleDefinitionsClientGetByIDResponse{
		RoleDefinition: armauthorization.RoleDefinition{
			Properties: &armauthorization.RoleDefinitionProperties{},
			ID:         &roleID,
			Name:       &roleName,
		},
	}, nil
}

func (m *mockProvider) CreateServicePrincipal(_ context.Context, _ string, _ time.Time, _ time.Time) (spID string, password string, err error) {
	id := generateUUID()
	pass := generateUUID()

	m.lock.Lock()
	defer m.lock.Unlock()

	m.servicePrincipals[id] = true

	return id, pass, nil
}

func (m *mockProvider) CreateApplication(_ context.Context, _ string) (models.Applicationable, error) {
	if m.failNextCreateApplication {
		m.failNextCreateApplication = false
		return nil, errors.New("Mock: fail to create application")
	}
	appObjID := generateUUID()
	appID := generateUUID()

	a := mocks.Applicationable{}

	a.On("GetAppId").Return(&appID)
	a.On("GetId").Return(&appObjID)

	m.lock.Lock()
	defer m.lock.Unlock()

	m.applications[appObjID] = appID

	return &a, nil
}

func (m *mockProvider) GetApplication(_ context.Context, objectID string) (models.Applicationable, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	appID := m.applications[objectID]

	a := mocks.Applicationable{}

	a.On("GetAppId").Return(&appID)
	a.On("GetId").Return(&objectID)

	return &a, nil
}

func (m *mockProvider) ListApplications(_ context.Context, _ string) ([]models.Applicationable, error) {
	return nil, nil
}

func (m *mockProvider) DeleteApplication(_ context.Context, applicationObjectID string, permanentlyDelete bool) error {
	delete(m.applications, applicationObjectID)
	m.deletedObjects[applicationObjectID] = true

	if permanentlyDelete {
		delete(m.deletedObjects, applicationObjectID)
	}
	return nil
}

func (m *mockProvider) DeleteServicePrincipal(_ context.Context, spObjectID string, permanentlyDelete bool) error {
	delete(m.servicePrincipals, spObjectID)
	m.deletedObjects[spObjectID] = true

	if permanentlyDelete {
		delete(m.deletedObjects, spObjectID)
	}
	return nil
}

func (m *mockProvider) AddApplicationPassword(_ context.Context, _ string, displayName string, endDateTime time.Time) (result models.PasswordCredentialable, err error) {
	keyID := uuid.New()
	pass := uuid.New().String()

	p := mocks.PasswordCredentialable{}
	p.On("GetKeyId").Return(&keyID)
	p.On("GetSecretText").Return(&pass)

	m.lock.Lock()
	defer m.lock.Unlock()
	m.passwords[keyID.String()] = pass

	return &p, nil
}

func (m *mockProvider) RemoveApplicationPassword(_ context.Context, _ string, keyID *uuid.UUID) (err error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	delete(m.passwords, keyID.String())

	return nil
}

func (m *mockProvider) deletedObjectExists(s string) bool {
	return m.deletedObjects[s]
}

func (m *mockProvider) appExists(s string) bool {
	_, ok := m.applications[s]
	return ok
}

func (m *mockProvider) passwordExists(s string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, ok := m.passwords[s]
	return ok
}

func (m *mockProvider) CreateRoleAssignment(_ context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	return armauthorization.RoleAssignmentsClientCreateResponse{
		RoleAssignment: armauthorization.RoleAssignment{
			Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
				Scope: &scope,
			},
			Name: &name,
			ID:   params.Properties.RoleDefinitionID,
		},
	}, nil
}

func (m *mockProvider) DeleteRoleAssignmentByID(_ context.Context, _ string) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
	return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, nil
}

// AddGroupMember adds a member to a Group.
func (m *mockProvider) AddGroupMember(_ context.Context, _ string, _ string) error {
	return nil
}

// RemoveGroupMember removes a member from a Group.
func (m *mockProvider) RemoveGroupMember(_ context.Context, _ string, _ string) error {
	return nil
}

// GetGroup gets group information from the directory.
func (m *mockProvider) GetGroup(_ context.Context, objectID string) (models.Groupable, error) {
	var groupName string
	s := strings.Split(objectID, "FAKE_GROUP-")
	if len(s) > 1 {
		groupName = s[1]
	}
	g := mocks.Groupable{}
	g.On("GetId").Return(
		&objectID)

	g.On("GetDisplayName").Return(
		&groupName)

	return &g, nil
}

// ListGroups gets list of groups for the current tenant.
func (m *mockProvider) ListGroups(_ context.Context, filter string) ([]models.Groupable, error) {
	reGroupName := regexp.MustCompile("displayName eq '(.*)'")

	match := reGroupName.FindAllStringSubmatch(filter, -1)
	if len(match) > 0 {
		name := match[0][1]
		if name == "multiple" {
			id1 := fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s-1", name)
			id2 := fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s-2", name)
			g1 := mocks.Groupable{}
			g1.On("GetId").Return(
				&id1,
			)
			g1.On("GetDisplayName").Return(&name)

			g2 := mocks.Groupable{}
			g2.On("GetId").Return(
				&id2,
			)
			g2.On("GetDisplayName").Return(&name)

			return []models.Groupable{
				&g1, &g2,
			}, nil
		}

		id := fmt.Sprintf("00000000-1111-2222-3333-444444444444FAKE_GROUP-%s", name)
		g := mocks.Groupable{}
		g.On("GetId").Return(
			&id,
		)
		g.On("GetDisplayName").Return(&name)

		return []models.Groupable{
			&g,
		}, nil
	}

	return []models.Groupable{}, nil

}

// errMockProvider simulates a normal provider which fails to associate a role,
// returning an error
type errMockProvider struct {
	*mockProvider
}

func newErrMockProvider() AzureProvider {
	return &errMockProvider{
		mockProvider: &mockProvider{
			applications:      make(map[string]string),
			servicePrincipals: make(map[string]bool),
			deletedObjects:    make(map[string]bool),
			passwords:         make(map[string]string),
		},
	}
}

// CreateRoleAssignment for the errMockProvider intentionally fails
func (e *errMockProvider) CreateRoleAssignment(_ context.Context, _ string, _ string, _ armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	return armauthorization.RoleAssignmentsClientCreateResponse{}, errors.New("PrincipalNotFound")
}

// ListRoleAssignments for the errMockProvider intentionally fails
func (e *errMockProvider) ListRoleAssignments(_ context.Context, _ string) ([]*armauthorization.RoleAssignment, error) {
	return []*armauthorization.RoleAssignment{}, errors.New("PrincipalNotFound")
}

// GetApplication for the errMockProvider only returns an application if that
// key is found, unlike mockProvider which returns the same application object
// id each time. Existing tests depend on the mockProvider behavior, which is
// why errMockProvider has it's own version.
func (e *errMockProvider) GetApplication(_ context.Context, applicationObjectID string) (models.Applicationable, error) {
	for s := range e.applications {
		if s == applicationObjectID {
			return nil, nil
		}
	}
	return nil, errors.New("not found")
}
