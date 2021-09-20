package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
)

const (
	// DefaultGraphMicrosoftComURI is the default URI used for the service MS Graph API
	DefaultGraphMicrosoftComURI = "https://graph.microsoft.com"
)

var _ ApplicationsClient = (*AppClient)(nil)
var _ GroupsClient = (*AppClient)(nil)

type AppClient struct {
	client authorization.BaseClient
}

func NewMSGraphApplicationClient(subscriptionId string, userAgentExtension string, auth autorest.Authorizer) (*AppClient, error) {
	client := authorization.NewWithBaseURI(DefaultGraphMicrosoftComURI, subscriptionId)
	client.Authorizer = auth

	if userAgentExtension != "" {
		err := client.AddToUserAgent(userAgentExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to add extension to user agent")
		}
	}

	ac := &AppClient{
		client: client,
	}
	return ac, nil
}

func (c *AppClient) AddToUserAgent(extension string) error {
	return c.client.AddToUserAgent(extension)
}

func (c *AppClient) GetApplication(ctx context.Context, applicationObjectID string) (result ApplicationResult, err error) {
	req, err := c.getApplicationPreparer(ctx, applicationObjectID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", nil, "Failure preparing request")
		return
	}

	resp, err := c.getApplicationSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", resp, "Failure sending request")
		return
	}

	result, err = c.getApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "GetApplication", resp, "Failure responding to request")
	}

	return
}

// CreateApplication create a new Azure application object.
func (c *AppClient) CreateApplication(ctx context.Context, displayName string) (result ApplicationResult, err error) {
	req, err := c.createApplicationPreparer(ctx, displayName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", nil, "Failure preparing request")
		return
	}

	resp, err := c.createApplicationSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", resp, "Failure sending request")
		return
	}

	result, err = c.createApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "CreateApplication", resp, "Failure responding to request")
	}

	return
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string) (result autorest.Response, err error) {
	req, err := c.deleteApplicationPreparer(ctx, applicationObjectID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", nil, "Failure preparing request")
		return
	}

	resp, err := c.deleteApplicationSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure sending request")
		return
	}

	result, err = c.deleteApplicationResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure responding to request")
	}

	return
}

func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result PasswordCredentialResult, err error) {
	req, err := c.addPasswordPreparer(ctx, applicationObjectID, displayName, endDateTime)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := c.addPasswordSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = c.addPasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure responding to request")
	}

	return
}

func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error) {
	req, err := c.removePasswordPreparer(ctx, applicationObjectID, keyID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := c.removePasswordSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = c.removePasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure responding to request")
	}

	return
}

func (c AppClient) getApplicationPreparer(ctx context.Context, applicationObjectID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}", pathParameters),
		c.client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c AppClient) getApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.client, req, sd...)
}

func (c AppClient) getApplicationResponder(resp *http.Response) (result ApplicationResult, err error) {
	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return result, err
}

func (c AppClient) addPasswordPreparer(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (*http.Request, error) {
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
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/addPassword", pathParameters),
		autorest.WithJSON(parameters),
		c.client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c AppClient) addPasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.client, req, sd...)
}

func (c AppClient) addPasswordResponder(resp *http.Response) (result PasswordCredentialResult, err error) {
	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (c AppClient) removePasswordPreparer(ctx context.Context, applicationObjectID string, keyID string) (*http.Request, error) {
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
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/removePassword", pathParameters),
		autorest.WithJSON(parameters),
		c.client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c AppClient) removePasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.client, req, sd...)
}

func (c AppClient) removePasswordResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return
}

func (c AppClient) createApplicationPreparer(ctx context.Context, displayName string) (*http.Request, error) {
	parameters := struct {
		DisplayName *string `json:"displayName"`
	}{
		DisplayName: to.StringPtr(displayName),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPath("/v1.0/applications"),
		autorest.WithJSON(parameters),
		c.client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c AppClient) createApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.client, req, sd...)
}

func (c AppClient) createApplicationResponder(resp *http.Response) (result ApplicationResult, err error) {
	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusCreated),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (c AppClient) deleteApplicationPreparer(ctx context.Context, applicationObjectID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsDelete(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}", pathParameters),
		c.client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c AppClient) deleteApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.client, req, sd...)
}

func (c AppClient) deleteApplicationResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return
}

func (c AppClient) AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error {
	if groupObjectID == "" {
		return fmt.Errorf("missing groupObjectID")
	}
	pathParams := map[string]interface{}{
		"groupObjectID": groupObjectID,
	}
	body := map[string]interface{}{
		"@odata.id": fmt.Sprintf("%s/v1.0/directoryObjects/%s", DefaultGraphMicrosoftComURI, memberObjectID),
	}
	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/groups/{groupObjectID}/members/$ref", pathParams),
		autorest.WithJSON(body),
		c.client.WithAuthorization())
	req, err := preparer.Prepare((&http.Request{}).WithContext(ctx))
	if err != nil {
		return err
	}

	sender := autorest.GetSendDecorators(req.Context(),
		autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...),
	)
	resp, err := autorest.SendWithSender(c.client, req, sender...)
	if err != nil {
		return err
	}

	respBody := map[string]interface{}{}

	return autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&respBody),
		autorest.ByClosing(),
	)
}

func (c AppClient) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error {
	if groupObjectID == "" {
		return fmt.Errorf("missing groupObjectID")
	}
	if memberObjectID == "" {
		return fmt.Errorf("missing memberObjectID")
	}
	pathParams := map[string]interface{}{
		"groupObjectID":  groupObjectID,
		"memberObjectID": memberObjectID,
	}
	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsDelete(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/groups/{groupObjectID}/members/{memberObjectID}/$ref", pathParams),
		c.client.WithAuthorization())
	req, err := preparer.Prepare((&http.Request{}).WithContext(ctx))
	if err != nil {
		return err
	}

	sender := autorest.GetSendDecorators(req.Context(),
		autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...),
	)
	resp, err := autorest.SendWithSender(c.client, req, sender...)
	if err != nil {
		return err
	}

	return autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByClosing(),
	)
}

// groupResponse is a struct representation of the data we care about coming back from
// the ms-graph API. This is not the same as `Group` because this information is
// slightly different from the AAD implementation and there should be an abstraction
// between the ms-graph API itself and the API this package presents.
type groupResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

func (c AppClient) GetGroup(ctx context.Context, groupID string) (result Group, err error) {
	if groupID == "" {
		return Group{}, fmt.Errorf("missing groupID")
	}
	pathParams := map[string]interface{}{
		"groupID": groupID,
	}
	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPathParameters("/v1.0/groups/{groupID}", pathParams),
		c.client.WithAuthorization())
	req, err := preparer.Prepare((&http.Request{}).WithContext(ctx))
	if err != nil {
		return Group{}, err
	}

	sender := autorest.GetSendDecorators(req.Context(),
		autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...),
	)
	resp, err := autorest.SendWithSender(c.client, req, sender...)
	if err != nil {
		return Group{}, err
	}

	groupResp := groupResponse{}

	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&groupResp),
		autorest.ByClosing(),
	)
	if err != nil {
		return Group{}, err
	}

	group := Group{
		ID:          groupResp.ID,
		DisplayName: groupResp.DisplayName,
	}

	return group, nil
}

// listGroupsResponse is a struct representation of the data we care about
// coming back from the ms-graph API
type listGroupsResponse struct {
	Groups []groupResponse `json:"value"`
}

func (c AppClient) ListGroups(ctx context.Context, filter string) (result []Group, err error) {
	filterArgs := url.Values{}
	if filter != "" {
		filterArgs.Set("$filter", filter)
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.client.BaseURI),
		autorest.WithPath(fmt.Sprintf("/v1.0/groups?%s", filterArgs.Encode())),
		c.client.WithAuthorization())
	req, err := preparer.Prepare((&http.Request{}).WithContext(ctx))
	if err != nil {
		return nil, err
	}

	sender := autorest.GetSendDecorators(req.Context(),
		autorest.DoRetryForStatusCodes(c.client.RetryAttempts, c.client.RetryDuration, autorest.StatusCodesForRetry...),
	)
	resp, err := autorest.SendWithSender(c.client, req, sender...)
	if err != nil {
		return nil, err
	}

	groupsResp := listGroupsResponse{}

	err = autorest.Respond(
		resp,
		c.client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&groupsResp),
		autorest.ByClosing(),
	)
	if err != nil {
		return nil, err
	}

	groups := []Group{}
	for _, rawGroup := range groupsResp.Groups {
		if rawGroup.ID == "" {
			return nil, fmt.Errorf("missing group ID from response")
		}

		group := Group{
			ID:          rawGroup.ID,
			DisplayName: rawGroup.DisplayName,
		}
		groups = append(groups, group)
	}
	return groups, nil
}
