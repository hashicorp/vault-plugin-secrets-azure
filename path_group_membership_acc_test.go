// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// TestGroupMembershipAcc_DynamicCredentials calls real Azure without injecting
// failures or adding retries. Absence of failures does not rule out propagation delays.
func TestGroupMembershipAcc_DynamicCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("set VAULT_ACC=1 to run against a disposable Azure environment")
	}
	skipIfMissingEnvVars(t,
		"AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET", "AZURE_GROUP_OBJECT_ID",
	)
	attempts := 20
	if value, ok := os.LookupEnv("AZURE_GROUP_TEST_ATTEMPTS"); ok {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 200 {
			t.Fatal("AZURE_GROUP_TEST_ATTEMPTS must be an integer between 1 and 200")
		}
		attempts = n
	}
	b, storage := newAccBackend(t)
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	c, err := b.getClient(ctx, storage)
	cancel()
	if err != nil {
		t.Fatalf("initializing Azure client failed (error type %T)", err)
	}
	observer := &groupMembershipAccProvider{AzureProvider: c.provider, t: t}
	c.provider = observer
	b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
		return observer, nil
	}

	groupID := os.Getenv("AZURE_GROUP_OBJECT_ID")
	roleName := "group-propagation-" + generateUUID()
	ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Storage:   storage,
		Data: map[string]interface{}{
			"azure_groups": encodeJSON([]AzureGroup{{ObjectID: groupID}}),
			"ttl":          "5m",
			"persist_app":  false,
		},
	})
	cancel()
	if err != nil || (resp != nil && resp.IsError()) {
		logGroupMembershipAccError(t, "role setup", err)
		t.Fatal("role setup failed; verify the group and management identity permissions")
	}

	successes, failures := 0, 0
	for i := 1; i <= attempts; i++ {
		observer.attempt = i
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + roleName,
			Storage:   storage,
		})
		cancel()
		if err != nil || resp == nil || resp.IsError() {
			failures++
			logGroupMembershipAccError(t, "credential issuance", err)
			t.Logf("timestamp=%s attempt=%d result=FAILURE elapsed=%s",
				start.UTC().Format(time.RFC3339Nano), i, time.Since(start))
		} else if clientID, ok := resp.Data["client_id"].(string); !ok || clientID == "" || resp.Secret == nil {
			failures++
			t.Logf("attempt=%d result=FAILURE reason=invalid_credential_response", i)
		} else {
			successes++
			t.Logf("timestamp=%s attempt=%d result=SUCCESS client_id=%s elapsed=%s",
				start.UTC().Format(time.RFC3339Nano), i, clientID, time.Since(start))
		}
		if i < attempts {
			time.Sleep(5 * time.Second)
		}
	}
	t.Logf("attempts=%d successes=%d failures=%d group_add_calls=%d group_add_failures=%d",
		attempts, successes, failures, observer.groupCalls, observer.groupFailures)
	if failures > 0 {
		t.Errorf("%d/%d credential requests failed; inspect group_add diagnostics to distinguish group failures from other stages", failures, attempts)
	}
}

type groupMembershipAccProvider struct {
	AzureProvider
	t             *testing.T
	attempt       int
	groupCalls    int
	groupFailures int
}

func (p *groupMembershipAccProvider) CreateApplicationWithPassword(ctx context.Context, name, audience, credentialName string, duration time.Duration, tags []string) (api.Application, error) {
	app, err := p.AzureProvider.CreateApplicationWithPassword(ctx, name, audience, credentialName, duration, tags)
	if app.AppObjectID != "" {
		p.t.Logf("attempt=%d created_app_object_id=%s", p.attempt, app.AppObjectID)
		p.t.Cleanup(func() {
			// Soft-delete directly so the unrelated purge/WAL behavior cannot hide
			// a successful group-assignment test or strand a failed attempt.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for i := 0; i < 3; i++ {
				err := p.AzureProvider.DeleteApplication(ctx, app.AppObjectID, false)
				if err == nil {
					return
				}
				graphErr := groupMembershipAccGraphError(err)
				if graphErr != nil && graphErr.ResponseInfo != nil && graphErr.ResponseInfo.StatusCode == 404 {
					return
				}
				logGroupMembershipAccError(p.t, "application cleanup", err)
				if i < 2 {
					select {
					case <-time.After(2 * time.Second):
					case <-ctx.Done():
						p.t.Errorf("cleanup timed out; manually inspect app_object_id=%s", app.AppObjectID)
						return
					}
				}
			}
			p.t.Errorf("cleanup failed; manually inspect app_object_id=%s", app.AppObjectID)
		})
	}
	return app, err
}

func (p *groupMembershipAccProvider) AddGroupMember(ctx context.Context, groupID, memberID string) error {
	p.groupCalls++
	err := p.AzureProvider.AddGroupMember(ctx, groupID, memberID)
	result := "SUCCESS"
	if err != nil {
		result = "FAILURE"
		p.groupFailures++
	}
	p.t.Logf("timestamp=%s attempt=%d operation=group_add result=%s group_object_id=%s member_object_id=%s",
		time.Now().UTC().Format(time.RFC3339Nano), p.attempt, result, groupID, memberID)
	if err != nil {
		logGroupMembershipAccError(p.t, "group_add", err)
	}
	return err
}

func groupMembershipAccGraphError(err error) *api.Error {
	var converted *api.Error
	if errors.As(err, &converted) {
		return converted
	}
	var graphErr *odataerrors.ODataError
	if errors.As(err, &graphErr) {
		converted, _ = api.ConvertToError(graphErr)
	}
	return converted
}

func logGroupMembershipAccError(t *testing.T, operation string, err error) {
	t.Helper()
	if graphErr := groupMembershipAccGraphError(err); graphErr != nil {
		t.Logf("operation=%s graph_error=%v", operation, graphErr.LoggerPairs())
	} else {
		t.Logf("operation=%s error_type=%T", operation, err)
	}
}
