package azuresecrets

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

func getTestBackend(t *testing.T) (*azureSecretBackend, logical.Storage) {
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
			MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	b.provider = &mockProvider{}

	return b, config.StorageView
}

type mockProvider struct{}

func (m *mockProvider) getApplicationClient() ApplicationClient {
	return &mockApplicationClient{}
}
func (m *mockProvider) getServicePrincipalClient() ServicePrincipalClient {
	return &mockServicePrincipalClient{}
}
func (m *mockProvider) getRoleAssignmentClient() RoleAssignmentClient {
	return &mockRoleAssignmentClient{}
}

type mockApplicationClient struct{}

func (m *mockApplicationClient) Create(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error) {
	return graphrbac.Application{
		AppID:    to.StringPtr("abc123"),
		ObjectID: to.StringPtr("xyz123"),
	}, nil
}

func (m *mockApplicationClient) Delete(ctx context.Context, applicationObjectID string) (autorest.Response, error) {
	return autorest.Response{}, nil
}

type mockServicePrincipalClient struct{}

func (m *mockServicePrincipalClient) Create(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	return graphrbac.ServicePrincipal{}, nil
}

type mockRoleAssignmentClient struct{}

func (m *mockRoleAssignmentClient) Create(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return authorization.RoleAssignment{}, nil
}
