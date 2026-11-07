// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/vault-plugin-secrets-azure/api"
)

func TestAppWALRollbackDeletionRetry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
	}{
		{name: "purge forbidden then success", statuses: []int{http.StatusForbidden, 0}},
		{name: "purge remains forbidden before success", statuses: []int{http.StatusForbidden, http.StatusForbidden, 0}},
		{name: "purge not found then success", statuses: []int{http.StatusNotFound, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			b, storage := getTestBackendMocked(t, true)
			objectID := generateUUID()
			calls := 0
			provider := &appWALDeletionTestProvider{
				AzureProvider: newMockProvider(),
			}
			b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
				return provider, nil
			}

			data := map[string]interface{}{
				"AppID":      generateUUID(),
				"AppObjID":   objectID,
				"Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			}
			req := &logical.Request{Storage: storage}
			for _, status := range tc.statuses {
				var deleteErr error
				if status != 0 {
					code := api.CodeAuthorizationRequestDenied.String()
					if status == http.StatusNotFound {
						code = api.CodeRequestResourceNotFound.String()
					}
					main := odataerrors.NewMainError()
					main.SetCode(&code)
					message := "application purge failed"
					main.SetMessage(&message)
					graphErr := odataerrors.NewODataError()
					graphErr.SetErrorEscaped(main)
					graphErr.SetStatusCode(status)
					deleteErr = graphErr
				}
				provider.delete = func(_ context.Context, id string, permanent bool) error {
					calls++
					require.Equal(t, objectID, id)
					require.True(t, permanent, "application WAL rollback must request permanent deletion")
					return deleteErr
				}

				err := b.walRollback(ctx, req, walAppKey, data)
				if deleteErr != nil {
					require.ErrorIs(t, err, deleteErr, "unexpired WAL rollback must preserve the purge failure for a later retry")
				} else {
					require.NoError(t, err)
				}
			}
			require.Equal(t, len(tc.statuses), calls)
		})
	}
}

type appWALDeletionTestProvider struct {
	AzureProvider
	delete func(context.Context, string, bool) error
}

func (p *appWALDeletionTestProvider) DeleteApplication(ctx context.Context, id string, permanent bool) error {
	return p.delete(ctx, id, permanent)
}
