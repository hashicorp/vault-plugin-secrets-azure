package api

import (
	"context"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
)

const (
	// defaultGraphMicrosoftComURI is the default URI used for the service MS Graph API
	DefaultGraphMicrosoftComURI = "https://graph.microsoft.com"
)

type AppClient struct {
	authorization.BaseClient
}

func NewGraphApplicationClient(subscriptionId string) AppClient {
	return AppClient{authorization.NewWithBaseURI(DefaultGraphMicrosoftComURI, subscriptionId)}
}

func (p *AppClient) GetApplication(ctx context.Context, applicationObjectID string) (result ApplicationResult, err error) {
	req, err := p.getApplicationPreparer(ctx, applicationObjectID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", nil, "Failure preparing request")
		return
	}

	resp, err := p.getApplicationSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", resp, "Failure sending request")
		return
	}

	result, err = p.getApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", resp, "Failure responding to request")
	}

	return
}

// CreateApplication create a new Azure application object.
func (p *AppClient) CreateApplication(ctx context.Context, displayName string) (result ApplicationResult, err error) {
	req, err := p.createApplicationPreparer(ctx, displayName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", nil, "Failure preparing request")
		return
	}

	resp, err := p.createApplicationSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", resp, "Failure sending request")
		return
	}

	result, err = p.createApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", resp, "Failure responding to request")
	}

	return
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (p *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string) (result autorest.Response, err error) {
	req, err := p.deleteApplicationPreparer(ctx, applicationObjectID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", nil, "Failure preparing request")
		return
	}

	resp, err := p.deleteApplicationSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure sending request")
		return
	}

	result, err = p.deleteApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure responding to request")
	}

	return
}

func (p *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result PasswordCredentialResult, err error) {
	req, err := p.addPasswordPreparer(ctx, applicationObjectID, displayName, endDateTime)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := p.addPasswordSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = p.addPasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure responding to request")
	}

	return
}

func (p *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error) {
	req, err := p.removePasswordPreparer(ctx, applicationObjectID, keyID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := p.removePasswordSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = p.removePasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure responding to request")
	}

	return
}

func (client AppClient) getApplicationPreparer(ctx context.Context, applicationObjectID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}", pathParameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client AppClient) getApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client AppClient) getApplicationResponder(resp *http.Response) (result ApplicationResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (client AppClient) addPasswordPreparer(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		PasswordCredential *PasswordCredential `json:"passwordCredential"`
	}{
		PasswordCredential: &PasswordCredential{
			DisplayName: to.StringPtr(displayName),
			EndDate:     &endDateTime,
		},
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/addPassword", pathParameters),
		autorest.WithJSON(parameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client AppClient) addPasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client AppClient) addPasswordResponder(resp *http.Response) (result PasswordCredentialResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (client AppClient) removePasswordPreparer(ctx context.Context, applicationObjectID string, keyID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		KeyID string `json:"keyId"`
	}{
		KeyID: keyID,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/removePassword", pathParameters),
		autorest.WithJSON(parameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client AppClient) removePasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client AppClient) removePasswordResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return
}

func (client AppClient) createApplicationPreparer(ctx context.Context, displayName string) (*http.Request, error) {
	parameters := struct {
		DisplayName *string `json:"displayName"`
	}{
		DisplayName: to.StringPtr(displayName),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPath("/v1.0/applications"),
		autorest.WithJSON(parameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client AppClient) createApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client AppClient) createApplicationResponder(resp *http.Response) (result ApplicationResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusCreated),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (client AppClient) deleteApplicationPreparer(ctx context.Context, applicationObjectID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}", pathParameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client AppClient) deleteApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client AppClient) deleteApplicationResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return
}
