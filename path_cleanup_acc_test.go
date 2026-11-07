// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestCleanupAcc_DynamicCredentials exercises real Azure application deletion
// without injecting failures. It explicitly repeats failed revocations, not the
// expiration scheduler or WAL rollback. A passing run may not encounter the bug.
//
// Requires VAULT_ACC=1, AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID,
// AZURE_CLIENT_SECRET, and AZURE_GROUP_OBJECT_ID in a disposable environment.
// AZURE_CLEANUP_TEST_ATTEMPTS defaults to 20 (1–200).
//
// WARNING: permanently deletes applications and service principals created by
// this test. Failed cleanup falls back to application soft deletion; inspect
// logged object IDs for resources requiring manual cleanup or purge.
//
// Run with:
//
//	go test -tags=enterprise . -run '^TestCleanupAcc_DynamicCredentials$' -count=1 -v -timeout=45m
func TestCleanupAcc_DynamicCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("set VAULT_ACC=1 to run against a disposable Azure environment")
	}
	skipIfMissingEnvVars(t,
		"AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET", "AZURE_GROUP_OBJECT_ID",
	)
	attempts := 20
	if value, ok := os.LookupEnv("AZURE_CLEANUP_TEST_ATTEMPTS"); ok {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 200 {
			t.Fatal("AZURE_CLEANUP_TEST_ATTEMPTS must be an integer between 1 and 200")
		}
		attempts = n
	}

	b, storage := newAccBackend(t)
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	c, err := b.getClient(ctx, storage)
	cancel()
	if err != nil {
		logGroupMembershipAccError(t, "initializing cleanup client", err)
		t.Fatal("initializing Azure client failed")
	}
	// Reuse the real-provider observer's per-application fallback cleanup.
	observer := &cleanupAccProvider{
		groupMembershipAccProvider: groupMembershipAccProvider{
			AzureProvider: c.provider,
			t:             t,
		},
	}
	c.provider = observer
	b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
		return observer, nil
	}

	roleName := "cleanup-repro-" + generateUUID()
	ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Storage:   storage,
		Data: map[string]interface{}{
			"azure_groups":       encodeJSON([]AzureGroup{{ObjectID: os.Getenv("AZURE_GROUP_OBJECT_ID")}}),
			"persist_app":        false,
			"permanently_delete": true,
			"ttl":                "5m",
		},
	})
	cancel()
	if err != nil {
		t.Fatalf("cleanup role setup failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("cleanup role setup failed: %v", resp.Error())
	}

	issued, issuanceFailures, firstTry, recovered, failed := 0, 0, 0, 0, 0
	for attempt := 1; attempt <= attempts; attempt++ {
		observer.attempt = attempt
		observer.round = 0
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		creds, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + roleName,
			Storage:   storage,
		})
		cancel()
		if err != nil || creds == nil || creds.IsError() || creds.Secret == nil {
			issuanceFailures++
			logGroupMembershipAccError(t, "cleanup credential issuance", err)
			t.Errorf("attempt=%d credential issuance failed; revocation was not exercised", attempt)
			continue
		}
		issued++
		// Match the serialization performed before Vault later revokes a secret.
		fakeSaveLoad(creds.Secret)

		const revokeRounds = 3
		for round := 1; round <= revokeRounds; round++ {
			observer.round = round
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.RevokeOperation,
				Path:      "creds/" + roleName,
				Storage:   storage,
				Secret:    creds.Secret,
			})
			cancel()
			if resp != nil && len(resp.Warnings) > 0 {
				t.Logf("attempt=%d round=%d revocation_warning_count=%d; inspect HTTP traces for service-principal/group cleanup failures",
					attempt, round, len(resp.Warnings))
			}
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Logf("timestamp=%s attempt=%d round=%d operation=revoke result=SUCCESS",
					time.Now().UTC().Format(time.RFC3339Nano), attempt, round)
				if round == 1 {
					firstTry++
				} else {
					recovered++
				}
				break
			}
			t.Logf("timestamp=%s attempt=%d round=%d operation=revoke result=FAILURE",
				time.Now().UTC().Format(time.RFC3339Nano), attempt, round)
			logGroupMembershipAccError(t, "cleanup revocation", err)
			if round == revokeRounds {
				failed++
				t.Errorf("attempt=%d revocation failed after %d rounds; inspect application_delete object IDs and HTTP traces", attempt, revokeRounds)
				break
			}
			time.Sleep(30 * time.Second)
		}
		if attempt < attempts {
			time.Sleep(5 * time.Second)
		}
	}
	t.Logf("attempts=%d issued=%d issuance_failures=%d revoked_first_try=%d revoked_after_retry=%d revocation_failures=%d",
		attempts, issued, issuanceFailures, firstTry, recovered, failed)
}

type cleanupAccProvider struct {
	groupMembershipAccProvider
	round int
}

func (p *cleanupAccProvider) DeleteApplication(ctx context.Context, objectID string, permanentlyDelete bool) error {
	err := p.AzureProvider.DeleteApplication(ctx, objectID, permanentlyDelete)
	result := "SUCCESS"
	if err != nil {
		result = "FAILURE"
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	p.t.Logf("timestamp=%s attempt=%d round=%d operation=application_delete app_object_id=%s permanently_delete=%t result=%s",
		timestamp, p.attempt, p.round, objectID, permanentlyDelete, result)
	if err != nil {
		logGroupMembershipAccError(p.t, "application_delete", err)
	}
	return err
}

// newAccBackend builds a backend wired to real Azure credentials from env.
func newAccBackend(t *testing.T) (*azureSecretBackend, logical.Storage) {
	t.Helper()

	s := new(logical.InmemStorage)
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      newTestSystemView(t),
		StorageView: s,
		Config:      make(map[string]string),
	}

	b := backend()
	require.NoError(t, b.Setup(context.Background(), config))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"subscription_id": os.Getenv("AZURE_SUBSCRIPTION_ID"),
			"tenant_id":       os.Getenv("AZURE_TENANT_ID"),
			"client_id":       os.Getenv("AZURE_CLIENT_ID"),
			"client_secret":   os.Getenv("AZURE_CLIENT_SECRET"),
		},
		Storage: s,
	})
	assertRespNoError(t, resp, err)

	return b, s
}
