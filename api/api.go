package api

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/date"
)

// AzureProvider is an interface to access underlying Azure client objects and supporting services.
// Where practical the original function signature is preserved. client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	ApplicationsClient
	ServicePrincipalsClient
	ADGroupsClient
	RoleAssignmentsClient
	RoleDefinitionsClient
}

type ApplicationsClient interface {
	GetApplication(ctx context.Context, applicationObjectID string) (result ApplicationResult, err error)
	CreateApplication(ctx context.Context, displayName string) (result ApplicationResult, err error)
	DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result PasswordCredentialResult, err error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error)
}

type ServicePrincipalsClient interface {
	CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error)
}

type ADGroupsClient interface {
	AddGroupMember(ctx context.Context, groupObjectID string, parameters graphrbac.GroupAddMemberParameters) (result autorest.Response, err error)
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (result autorest.Response, err error)
	GetGroup(ctx context.Context, objectID string) (result graphrbac.ADGroup, err error)
	ListGroups(ctx context.Context, filter string) (result []graphrbac.ADGroup, err error)
}

type RoleAssignmentsClient interface {
	CreateRoleAssignment(
		ctx context.Context,
		scope string,
		roleAssignmentName string,
		parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleID string) (authorization.RoleAssignment, error)
}

type RoleDefinitionsClient interface {
	ListRoles(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
	GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error)
}

type PasswordCredential struct {
	DisplayName *string `json:"displayName"`
	// StartDate - Start date.
	StartDate *date.Time `json:"startDateTime,omitempty"`
	// EndDate - End date.
	EndDate *date.Time `json:"endDateTime,omitempty"`
	// KeyID - Key ID.
	KeyID *string `json:"keyId,omitempty"`
	// Value - Key value.
	SecretText *string `json:"secretText,omitempty"`
}

type PasswordCredentialResult struct {
	autorest.Response `json:"-"`

	PasswordCredential
}

type ApplicationResult struct {
	autorest.Response `json:"-"`

	AppID               *string               `json:"appId,omitempty"`
	ID                  *string               `json:"id,omitempty"`
	PasswordCredentials []*PasswordCredential `json:"passwordCredentials,omitempty"`
}
