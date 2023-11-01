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
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	auth "github.com/microsoftgraph/msgraph-sdk-go-core/authentication"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type ApplicationsClient interface {
	GetApplication(ctx context.Context, clientID string) (Application, error)
	CreateApplication(ctx context.Context, displayName string) (Application, error)
	DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error
	ListApplications(ctx context.Context, filter string) ([]Application, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredential, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

var _ ApplicationsClient = (*AppClient)(nil)
var _ GroupsClient = (*AppClient)(nil)
var _ ServicePrincipalClient = (*AppClient)(nil)

type AppClient struct {
	client *msgraphsdkgo.GraphServiceClient
}

type Application struct {
	ID                  string
	AppID               string
	AppObjectID         string
	Description         string
	DisplayName         string
	PasswordCredentials []PasswordCredential
}

type PasswordCredential struct {
	DisplayName string
	EndDate     time.Time
	KeyID       string
	SecretText  string
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

func (c *AppClient) GetApplication(ctx context.Context, clientID string) (Application, error) {
	filter := fmt.Sprintf("appId eq '%s'", clientID)
	req := applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	}

	resp, err := c.client.Applications().Get(ctx, &req)
	if err != nil {
		return Application{}, err
	}

	apps := resp.GetValue()
	if len(apps) == 0 {
		return Application{}, fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return Application{}, fmt.Errorf("multiple applications found - double check your client_id")
	}

	app := apps[0]

	application := Application{
		ID:                  *app.GetId(),
		AppID:               *app.GetAppId(),
		AppObjectID:         *app.GetId(),
		Description:         *app.GetDescription(),
		DisplayName:         *app.GetDisplayName(),
		PasswordCredentials: getPasswordCredentialsForApplication(app),
	}

	return application, nil
}

func (c *AppClient) ListApplications(ctx context.Context, filter string) ([]Application, error) {

	req := &applications.ApplicationsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}
	configuration := &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: req,
	}
	resp, err := c.client.Applications().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}

	var apps []Application
	for _, app := range resp.GetValue() {
		apps = append(apps, Application{
			ID:                  *app.GetId(),
			AppID:               *app.GetAppId(),
			AppObjectID:         *app.GetId(),
			Description:         *app.GetDescription(),
			DisplayName:         *app.GetDisplayName(),
			PasswordCredentials: getPasswordCredentialsForApplication(app),
		})
	}

	return apps, nil
}

// CreateApplication create a new Azure application object.
func (c *AppClient) CreateApplication(ctx context.Context, displayName string) (Application, error) {
	requestBody := models.NewApplication()
	requestBody.SetDisplayName(&displayName)

	resp, err := c.client.Applications().Post(ctx, requestBody, nil)
	if err != nil {
		return Application{}, err
	}

	return Application{
		ID:                  *resp.GetId(),
		AppID:               *resp.GetAppId(),
		AppObjectID:         *resp.GetId(),
		Description:         *resp.GetDescription(),
		DisplayName:         *resp.GetDisplayName(),
		PasswordCredentials: getPasswordCredentialsForApplication(resp),
	}, nil
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error {
	err := c.client.Applications().ByApplicationId(applicationObjectID).Delete(ctx, nil)

	if permanentlyDelete {
		e := c.client.Directory().DeletedItems().ByDirectoryObjectId(applicationObjectID).Delete(ctx, nil)
		merr := multierror.Append(err, e)
		return merr.ErrorOrNil()
	}

	return err
}

func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredential, error) {
	requestBody := applications.NewItemAddPasswordPostRequestBody()
	passwordCredential := models.NewPasswordCredential()
	passwordCredential.SetDisplayName(&displayName)
	passwordCredential.SetEndDateTime(&endDateTime)
	requestBody.SetPasswordCredential(passwordCredential)

	resp, err := c.client.Applications().ByApplicationId(applicationObjectID).AddPassword().Post(ctx, requestBody, nil)
	if err != nil {
		return PasswordCredential{}, err
	}

	return PasswordCredential{
		SecretText:  *resp.GetSecretText(),
		EndDate:     *resp.GetEndDateTime(),
		KeyID:       resp.GetKeyId().String(),
		DisplayName: *resp.GetDisplayName(),
	}, nil
}

func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error {
	requestBody := applications.NewItemRemovePasswordPostRequestBody()
	kid, err := uuid.Parse(keyID)
	if err != nil {
		return err
	}

	requestBody.SetKeyId(&kid)

	return c.client.Applications().ByApplicationId(applicationObjectID).RemovePassword().Post(ctx, requestBody, nil)
}

func getPasswordCredentialsForApplication(app models.Applicationable) []PasswordCredential {
	var appCredentials []PasswordCredential
	for _, cred := range app.GetPasswordCredentials() {
		appCredentials = append(appCredentials, PasswordCredential{
			SecretText:  *cred.GetSecretText(),
			EndDate:     *cred.GetEndDateTime(),
			KeyID:       cred.GetKeyId().String(),
			DisplayName: *cred.GetDisplayName(),
		})
	}
	return appCredentials
}
