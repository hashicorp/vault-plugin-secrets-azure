// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/hashicorp/vault-plugin-secrets-azure/api (interfaces: AzureProvider)

// Package azuresecrets is a generated GoMock package.
package azuresecrets

import (
	context "context"
	reflect "reflect"
	time "time"

	authorization "github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2020-10-01/authorization"
	gomock "github.com/golang/mock/gomock"
	api "github.com/hashicorp/vault-plugin-secrets-azure/api"
)

// MockAzureProvider is a mock of AzureProvider interface.
type MockAzureProvider struct {
	ctrl     *gomock.Controller
	recorder *MockAzureProviderMockRecorder
}

// MockAzureProviderMockRecorder is the mock recorder for MockAzureProvider.
type MockAzureProviderMockRecorder struct {
	mock *MockAzureProvider
}

// NewMockAzureProvider creates a new mock instance.
func NewMockAzureProvider(ctrl *gomock.Controller) *MockAzureProvider {
	mock := &MockAzureProvider{ctrl: ctrl}
	mock.recorder = &MockAzureProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAzureProvider) EXPECT() *MockAzureProviderMockRecorder {
	return m.recorder
}

// AddApplicationPassword mocks base method.
func (m *MockAzureProvider) AddApplicationPassword(arg0 context.Context, arg1, arg2 string, arg3 time.Time) (api.PasswordCredentialResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddApplicationPassword", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(api.PasswordCredentialResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddApplicationPassword indicates an expected call of AddApplicationPassword.
func (mr *MockAzureProviderMockRecorder) AddApplicationPassword(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddApplicationPassword", reflect.TypeOf((*MockAzureProvider)(nil).AddApplicationPassword), arg0, arg1, arg2, arg3)
}

// AddGroupMember mocks base method.
func (m *MockAzureProvider) AddGroupMember(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddGroupMember", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddGroupMember indicates an expected call of AddGroupMember.
func (mr *MockAzureProviderMockRecorder) AddGroupMember(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddGroupMember", reflect.TypeOf((*MockAzureProvider)(nil).AddGroupMember), arg0, arg1, arg2)
}

// CreateApplication mocks base method.
func (m *MockAzureProvider) CreateApplication(arg0 context.Context, arg1 string) (api.ApplicationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateApplication", arg0, arg1)
	ret0, _ := ret[0].(api.ApplicationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateApplication indicates an expected call of CreateApplication.
func (mr *MockAzureProviderMockRecorder) CreateApplication(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateApplication", reflect.TypeOf((*MockAzureProvider)(nil).CreateApplication), arg0, arg1)
}

// CreateRoleAssignment mocks base method.
func (m *MockAzureProvider) CreateRoleAssignment(arg0 context.Context, arg1, arg2 string, arg3 authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRoleAssignment", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateRoleAssignment indicates an expected call of CreateRoleAssignment.
func (mr *MockAzureProviderMockRecorder) CreateRoleAssignment(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRoleAssignment", reflect.TypeOf((*MockAzureProvider)(nil).CreateRoleAssignment), arg0, arg1, arg2, arg3)
}

// CreateServicePrincipal mocks base method.
func (m *MockAzureProvider) CreateServicePrincipal(arg0 context.Context, arg1 string, arg2, arg3 time.Time) (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateServicePrincipal", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateServicePrincipal indicates an expected call of CreateServicePrincipal.
func (mr *MockAzureProviderMockRecorder) CreateServicePrincipal(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateServicePrincipal", reflect.TypeOf((*MockAzureProvider)(nil).CreateServicePrincipal), arg0, arg1, arg2, arg3)
}

// DeleteApplication mocks base method.
func (m *MockAzureProvider) DeleteApplication(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteApplication", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteApplication indicates an expected call of DeleteApplication.
func (mr *MockAzureProviderMockRecorder) DeleteApplication(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteApplication", reflect.TypeOf((*MockAzureProvider)(nil).DeleteApplication), arg0, arg1)
}

// DeleteRoleAssignmentByID mocks base method.
func (m *MockAzureProvider) DeleteRoleAssignmentByID(arg0 context.Context, arg1 string) (authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRoleAssignmentByID", arg0, arg1)
	ret0, _ := ret[0].(authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteRoleAssignmentByID indicates an expected call of DeleteRoleAssignmentByID.
func (mr *MockAzureProviderMockRecorder) DeleteRoleAssignmentByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRoleAssignmentByID", reflect.TypeOf((*MockAzureProvider)(nil).DeleteRoleAssignmentByID), arg0, arg1)
}

// GetApplication mocks base method.
func (m *MockAzureProvider) GetApplication(arg0 context.Context, arg1 string) (api.ApplicationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetApplication", arg0, arg1)
	ret0, _ := ret[0].(api.ApplicationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetApplication indicates an expected call of GetApplication.
func (mr *MockAzureProviderMockRecorder) GetApplication(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetApplication", reflect.TypeOf((*MockAzureProvider)(nil).GetApplication), arg0, arg1)
}

// GetGroup mocks base method.
func (m *MockAzureProvider) GetGroup(arg0 context.Context, arg1 string) (api.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroup", arg0, arg1)
	ret0, _ := ret[0].(api.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroup indicates an expected call of GetGroup.
func (mr *MockAzureProviderMockRecorder) GetGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroup", reflect.TypeOf((*MockAzureProvider)(nil).GetGroup), arg0, arg1)
}

// GetRoleDefinitionByID mocks base method.
func (m *MockAzureProvider) GetRoleDefinitionByID(arg0 context.Context, arg1 string) (authorization.RoleDefinition, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRoleDefinitionByID", arg0, arg1)
	ret0, _ := ret[0].(authorization.RoleDefinition)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoleDefinitionByID indicates an expected call of GetRoleDefinitionByID.
func (mr *MockAzureProviderMockRecorder) GetRoleDefinitionByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoleDefinitionByID", reflect.TypeOf((*MockAzureProvider)(nil).GetRoleDefinitionByID), arg0, arg1)
}

// ListApplications mocks base method.
func (m *MockAzureProvider) ListApplications(arg0 context.Context, arg1 string) ([]api.ApplicationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListApplications", arg0, arg1)
	ret0, _ := ret[0].([]api.ApplicationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListApplications indicates an expected call of ListApplications.
func (mr *MockAzureProviderMockRecorder) ListApplications(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListApplications", reflect.TypeOf((*MockAzureProvider)(nil).ListApplications), arg0, arg1)
}

// ListGroups mocks base method.
func (m *MockAzureProvider) ListGroups(arg0 context.Context, arg1 string) ([]api.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListGroups", arg0, arg1)
	ret0, _ := ret[0].([]api.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListGroups indicates an expected call of ListGroups.
func (mr *MockAzureProviderMockRecorder) ListGroups(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListGroups", reflect.TypeOf((*MockAzureProvider)(nil).ListGroups), arg0, arg1)
}

// ListRoleDefinitions mocks base method.
func (m *MockAzureProvider) ListRoleDefinitions(arg0 context.Context, arg1, arg2 string) ([]authorization.RoleDefinition, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRoleDefinitions", arg0, arg1, arg2)
	ret0, _ := ret[0].([]authorization.RoleDefinition)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListRoleDefinitions indicates an expected call of ListRoleDefinitions.
func (mr *MockAzureProviderMockRecorder) ListRoleDefinitions(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRoleDefinitions", reflect.TypeOf((*MockAzureProvider)(nil).ListRoleDefinitions), arg0, arg1, arg2)
}

// RemoveApplicationPassword mocks base method.
func (m *MockAzureProvider) RemoveApplicationPassword(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveApplicationPassword", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveApplicationPassword indicates an expected call of RemoveApplicationPassword.
func (mr *MockAzureProviderMockRecorder) RemoveApplicationPassword(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveApplicationPassword", reflect.TypeOf((*MockAzureProvider)(nil).RemoveApplicationPassword), arg0, arg1, arg2)
}

// RemoveGroupMember mocks base method.
func (m *MockAzureProvider) RemoveGroupMember(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveGroupMember", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveGroupMember indicates an expected call of RemoveGroupMember.
func (mr *MockAzureProviderMockRecorder) RemoveGroupMember(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveGroupMember", reflect.TypeOf((*MockAzureProvider)(nil).RemoveGroupMember), arg0, arg1, arg2)
}
