// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
)

type ServicePrincipalClient interface {
	// CreateServicePrincipal in Azure. The password returned is the actual password that the appID was created with
	CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (id string, password string, err error)
	DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error
}

func (c *AppClient) CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (string, string, error) {
	spReq := models.NewServicePrincipal()
	spReq.SetAppId(&appID)

	sp, err := c.client.ServicePrincipals().Post(ctx, spReq, nil)
	if err != nil {
		return "", "", err
	}

	spID := sp.GetId()

	passwordReq := serviceprincipals.NewItemAddPasswordPostRequestBody()
	passwordCredential := models.NewPasswordCredential()
	passwordCredential.SetStartDateTime(&startDate)
	passwordCredential.SetEndDateTime(&endDate)

	passwordReq.SetPasswordCredential(passwordCredential)

	password, err := c.client.ServicePrincipals().ByServicePrincipalId(*spID).AddPassword().Post(context.Background(), passwordReq, nil)

	if err != nil {
		e := c.DeleteServicePrincipal(ctx, *spID, false)
		merr := multierror.Append(err, e)
		return "", "", merr.ErrorOrNil()
	}
	return *spID, *password.GetSecretText(), nil
}

func (c *AppClient) DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error {
	err := c.client.ServicePrincipals().ByServicePrincipalId(spObjectID).Delete(ctx, nil)

	if permanentlyDelete {
		e := c.client.Directory().DeletedItems().ByDirectoryObjectId(spObjectID).Delete(ctx, nil)
		merr := multierror.Append(err, e)
		return merr.ErrorOrNil()
	}

	return err
}

func (c *AppClient) ListServicePrincipals(ctx context.Context, spObjectID string) ([]models.ServicePrincipalable, error) {
	filter := fmt.Sprintf("appId eq '%s'", spObjectID)
	requestParameters := &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}

	headers := abstractions.NewRequestHeaders()
	headers.Add("ConsistencyLevel", "eventual")

	configuration := &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		Headers:         headers,
		QueryParameters: requestParameters,
	}

	spList, err := c.client.ServicePrincipals().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}
	return spList.GetValue(), nil
}

func (c *AppClient) GetServicePrincipalByID(ctx context.Context, spObjectID string) (models.ServicePrincipalable, error) {
	return c.client.ServicePrincipals().ByServicePrincipalId(spObjectID).Get(ctx, nil)
}
