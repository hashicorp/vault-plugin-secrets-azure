// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/stretchr/testify/require"
)

func TestDeleteApplication(t *testing.T) {
	const activePath = "/v1.0/applications/test-app"
	const deletedPath = "/v1.0/directory/deletedItems/test-app"
	for _, tc := range []struct {
		name       string
		permanent  bool
		statuses   []int
		paths      []string
		wantStatus int
	}{
		{name: "soft delete", statuses: []int{204}, paths: []string{activePath}},
		{name: "soft delete not found remains an error", statuses: []int{404}, paths: []string{activePath}, wantStatus: 404},
		{name: "permanent delete", permanent: true, statuses: []int{204, 204}, paths: []string{activePath, deletedPath}},
		{name: "resume purge after active not found", permanent: true, statuses: []int{404, 204}, paths: []string{activePath, deletedPath}},
		{name: "soft delete forbidden stops purge", permanent: true, statuses: []int{403}, paths: []string{activePath}, wantStatus: 403},
		{name: "purge forbidden", permanent: true, statuses: []int{204, 403}, paths: []string{activePath, deletedPath}, wantStatus: 403},
		{name: "resumed purge forbidden", permanent: true, statuses: []int{404, 403}, paths: []string{activePath, deletedPath}, wantStatus: 403},
		{name: "purge not found remains an error", permanent: true, statuses: []int{404, 404}, paths: []string{activePath, deletedPath}, wantStatus: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, paths := applicationDeletionTestClient(t, tc.statuses)
			err := c.DeleteApplication(context.Background(), "test-app", tc.permanent)
			if tc.wantStatus == 0 {
				require.NoError(t, err)
			} else {
				graphErr, ok := ConvertToError(err)
				require.True(t, ok, "expected Graph error, got %T", err)
				require.NotNil(t, graphErr.ResponseInfo)
				require.Equal(t, tc.wantStatus, graphErr.ResponseInfo.StatusCode)
			}
			require.Equal(t, tc.paths, *paths)
		})
	}
}

func TestDeleteApplicationRetryAfterPurgeFailure(t *testing.T) {
	c, paths := applicationDeletionTestClient(t, []int{204, 403, 404, 204})
	err := c.DeleteApplication(context.Background(), "test-app", true)
	graphErr, ok := ConvertToError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusForbidden, graphErr.ResponseInfo.StatusCode)

	require.NoError(t, c.DeleteApplication(context.Background(), "test-app", true))
	require.Equal(t, []string{
		"/v1.0/applications/test-app",
		"/v1.0/directory/deletedItems/test-app",
		"/v1.0/applications/test-app",
		"/v1.0/directory/deletedItems/test-app",
	}, *paths)
}

func applicationDeletionTestClient(t *testing.T, statuses []int) (*MSGraphClient, *[]string) {
	t.Helper()
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodDelete || len(paths) > len(statuses) {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		status := statuses[len(paths)-1]
		if status == http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		code := "Authorization_RequestDenied"
		if status == http.StatusNotFound {
			code = "Request_ResourceNotFound"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, err := fmt.Fprintf(w, `{"error":{"code":%q,"message":"test Graph error"}}`, code)
		if err != nil {
			t.Errorf("writing Graph response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	adapter, err := msgraphsdkgo.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		&authentication.AnonymousAuthenticationProvider{}, nil, nil, server.Client(),
	)
	require.NoError(t, err)
	adapter.SetBaseUrl(server.URL + "/v1.0")
	return &MSGraphClient{client: msgraphsdkgo.NewGraphServiceClient(adapter)}, &paths
}
