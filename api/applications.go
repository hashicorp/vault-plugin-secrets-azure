// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	auth "github.com/microsoftgraph/msgraph-sdk-go-core/authentication"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type ApplicationsClient interface {
	GetApplication(ctx context.Context, clientID string) (models.Applicationable, error)
	CreateApplication(ctx context.Context, displayName string) (models.Applicationable, error)
	DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error
	ListApplications(ctx context.Context, filter string) ([]models.Applicationable, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (models.PasswordCredentialable, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error
}

var _ ApplicationsClient = (*AppClient)(nil)
var _ GroupsClient = (*AppClient)(nil)
var _ ServicePrincipalClient = (*AppClient)(nil)

type AppClient struct {
	client *msgraphsdkgo.GraphServiceClient
}

// Reference: https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
func GetGraphURI(env string) (string, error) {
	switch env {
	case "AzurePublicCloud", "":
		return "https://graph.microsoft.com", nil
	case "AzureUSGovernmentCloud":
		return "https://graph.microsoft.us", nil
	case "AzureGermanCloud":
		return "https://graph.microsoft.de", nil
	case "AzureChinaCloud":
		return "https://microsoftgraph.chinacloudapi.cn", nil
	default:
		return "", fmt.Errorf("environment '%s' unknown", env)
	}
}

// NewMSGraphApplicationClient returns a new AppClient configured to interact with
// the Microsoft Graph API. It can be configured to target alternative national cloud
// deployments via graphURI. For details on the client configuration see
// https://learn.microsoft.com/en-us/graph/sdks/national-clouds
func NewMSGraphApplicationClient(graphURI string, creds azcore.TokenCredential) (*AppClient, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", graphURI),
	}

	authProvider, err := auth.NewAzureIdentityAuthenticationProviderWithScopes(creds, scopes)
	if err != nil {
		return nil, err
	}

	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(authProvider)
	if err != nil {
		return nil, err
	}

	adapter.SetBaseUrl(fmt.Sprintf("%s/v1.0", graphURI))
	client := msgraphsdkgo.NewGraphServiceClient(adapter)

	ac := &AppClient{
		client: client,
	}
	return ac, nil
}

func (c *AppClient) GetApplication(ctx context.Context, clientID string) (models.Applicationable, error) {
	filter := fmt.Sprintf("appId eq '%s'", clientID)
	req := applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	}

	resp, err := c.client.Applications().Get(ctx, &req)
	if err != nil {
		return nil, err
	}

	apps := resp.GetValue()
	if len(apps) == 0 {
		return nil, fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return nil, fmt.Errorf("multiple applications found - double check your client_id")
	}

	return apps[0], nil
}

func (c *AppClient) ListApplications(ctx context.Context, filter string) ([]models.Applicationable, error) {
	headers := abstractions.NewRequestHeaders()
	headers.Add("ConsistencyLevel", "eventual")

	req := &applications.ApplicationsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}
	configuration := &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		Headers:         headers,
		QueryParameters: req,
	}
	applications, err := c.client.Applications().Get(ctx, configuration)

	if err != nil {
		return nil, err
	}

	return applications.GetValue(), nil
}

// CreateApplication create a new Azure application object.
func (c *AppClient) CreateApplication(ctx context.Context, displayName string) (models.Applicationable, error) {
	requestBody := models.NewApplication()
	requestBody.SetDisplayName(&displayName)

	return c.client.Applications().Post(ctx, requestBody, nil)
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error {
	err := c.client.Applications().ByApplicationId(applicationObjectID).Delete(context.Background(), nil)

	if permanentlyDelete {
		e := c.client.Directory().DeletedItems().ByDirectoryObjectId(applicationObjectID).Delete(context.Background(), nil)
		merr := multierror.Append(err, e)
		return merr.ErrorOrNil()
	}

	return err
}

func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (models.PasswordCredentialable, error) {
	requestBody := applications.NewItemAddPasswordPostRequestBody()
	passwordCredential := models.NewPasswordCredential()
	passwordCredential.SetDisplayName(&displayName)
	passwordCredential.SetEndDateTime(&endDateTime)
	requestBody.SetPasswordCredential(passwordCredential)

	resp, err := c.client.Applications().ByApplicationId(applicationObjectID).AddPassword().Post(ctx, requestBody, nil)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error {
	requestBody := applications.NewItemRemovePasswordPostRequestBody()
	requestBody.SetKeyId(keyID)

	return c.client.Applications().ByApplicationId(applicationObjectID).RemovePassword().Post(ctx, requestBody, nil)
}
