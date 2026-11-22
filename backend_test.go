// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/rotation"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultLeaseTTLHr         = 1 * time.Hour
	maxLeaseTTLHr             = 12 * time.Hour
	defaultTestTTL            = 300
	defaultTestMaxTTL         = 3600
	defaultTestExplicitMaxTTL = 7200
)

var (
	testClientID     = "testClientId"
	testClientSecret = "testClientSecret"
)

type testSystemViewEnt struct {
	logical.StaticSystemView
}

func (d testSystemViewEnt) GenerateIdentityToken(_ context.Context, _ *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	return &pluginutil.IdentityTokenResponse{}, nil
}

func (d testSystemViewEnt) RegisterRotationJob(_ context.Context, _ *rotation.RotationJobConfigureRequest) (string, error) {
	return "", automatedrotationutil.ErrRotationManagerUnsupported
}

func (d testSystemViewEnt) DeregisterRotationJob(_ context.Context, _ *rotation.RotationJobDeregisterRequest) error {
	return nil
}

func newTestSystemView(t *testing.T) logical.SystemView {
	t.Helper()

	sysView := &testSystemViewEnt{}
	sysView.DefaultLeaseTTLVal = defaultLeaseTTLHr
	sysView.MaxLeaseTTLVal = maxLeaseTTLHr
	return sysView
}

func getTestBackendMocked(t *testing.T, initConfig bool) (*azureSecretBackend, logical.Storage) {
	b := backend()
	sysView := testSystemViewEnt{}
	sysView.DefaultLeaseTTLVal = defaultLeaseTTLHr
	sysView.MaxLeaseTTLVal = maxLeaseTTLHr

	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &sysView,
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.settings = new(clientSettings)
	mockProvider := newMockProvider()
	b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
		return mockProvider, nil
	}

	if initConfig {
		cfg := map[string]interface{}{
			"subscription_id":  generateUUID(),
			"tenant_id":        generateUUID(),
			"client_id":        testClientID,
			"client_secret":    testClientSecret,
			"environment":      "AZURECHINACLOUD",
			"ttl":              defaultTestTTL,
			"max_ttl":          defaultTestMaxTTL,
			"explicit_max_ttl": defaultTestExplicitMaxTTL,
		}

		testConfigCreate(t, b, config.StorageView, cfg, false)
	}

	return b, config.StorageView
}

func getTestBackendWithStorage(t *testing.T, initConfig bool, storage logical.Storage, withEvents bool) (*azureSecretBackend, logical.Storage, *logical.MockEventSender, *mockProvider) {
	t.Helper()

	if storage == nil {
		storage = &logical.InmemStorage{}
	}

	var eventSender *logical.MockEventSender
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      newTestSystemView(t),
		StorageView: storage,
		Config:      make(map[string]string),
	}
	if withEvents {
		eventSender = logical.NewMockEventSender()
		config.EventsSender = eventSender
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	retBackend := b.(*azureSecretBackend)
	mockProvider := newMockProvider().(*mockProvider)
	retBackend.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
		return mockProvider, nil
	}

	if initConfig {
		cfg := map[string]interface{}{
			"subscription_id":  generateUUID(),
			"tenant_id":        generateUUID(),
			"client_id":        testClientID,
			"client_secret":    testClientSecret,
			"environment":      "AZURECHINACLOUD",
			"ttl":              defaultTestTTL,
			"max_ttl":          defaultTestMaxTTL,
			"explicit_max_ttl": defaultTestExplicitMaxTTL,
		}

		testConfigCreate(t, retBackend, config.StorageView, cfg, false)
	}

	return retBackend, config.StorageView, eventSender, mockProvider
}

func getTestBackend(t *testing.T) (*azureSecretBackend, logical.Storage) {
	b := backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr,
			MaxLeaseTTLVal:     maxLeaseTTLHr,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPeriodicFuncNilConfig(t *testing.T) {
	b := backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr,
			MaxLeaseTTLVal:     maxLeaseTTLHr,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.settings = new(clientSettings)
	mockProvider := newMockProvider()
	b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
		return mockProvider, nil
	}

	err = b.periodicFunc(context.Background(), &logical.Request{
		Storage: config.StorageView,
	})
	if err != nil {
		t.Fatalf("periodicFunc error not nil, it should have been: %v", err)
	}
}

func TestSameClientID(t *testing.T) {
	id := generateUUID()

	tests := map[string]struct {
		a, b string
		want bool
	}{
		"identical":              {id, id, true},
		"upper vs lower":         {strings.ToUpper(id), strings.ToLower(id), true},
		"mixed vs lower":         {strings.ToUpper(id[:18]) + id[18:], id, true},
		"braced and no hyphens":  {"{" + strings.ToUpper(id) + "}", strings.ReplaceAll(id, "-", ""), true},
		"surrounding whitespace": {" " + strings.ToUpper(id) + " ", id, true},
		"distinct uuids":         {id, generateUUID(), false},
		"non-uuid case variant":  {"testClientId", "TESTCLIENTID", true},
		"non-uuid distinct":      {"testClientId", "otherClientId", false},
		"uuid vs non-uuid":       {id, "testClientId", false},
		"empty vs uuid":          {"", id, false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := sameClientID(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameClientID(%q, %q) = %t, want %t", tc.a, tc.b, got, tc.want)
			}
			if got := sameClientID(tc.b, tc.a); got != tc.want {
				t.Fatalf("sameClientID(%q, %q) = %t, want %t", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

// getTestBackendWithUUIDClientID returns a backend whose configured client_id
// is rootClientID.
func getTestBackendWithUUIDClientID(t *testing.T, rootClientID string) (*azureSecretBackend, logical.Storage, *mockProvider) {
	t.Helper()

	b, s, _, mp := getTestBackendWithStorage(t, false, nil, false)
	testConfigCreate(t, b, s, map[string]interface{}{
		"subscription_id": generateUUID(),
		"tenant_id":       generateUUID(),
		"client_id":       rootClientID,
		"client_secret":   testClientSecret,
	}, false)

	return b, s, mp
}

// caseVariants returns representations of id that differ only in letter case.
func caseVariants(id string) map[string]string {
	return map[string]string{
		"upper": strings.ToUpper(id),
		"lower": strings.ToLower(id),
		"mixed": strings.ToUpper(id[:18]) + strings.ToLower(id[18:]),
	}
}

// TestRootCredentialTarget_CaseVariantBlocked verifies that the self-target
// guard rejects every textual case form of Vault's own client ID at role write,
// and at credential issuance for roles stored before the guard was effective,
// without ever creating a password.
func TestRootCredentialTarget_CaseVariantBlocked(t *testing.T) {
	rootID := strings.ToLower(generateUUID())

	for configName, configured := range caseVariants(rootID) {
		for graphName, fromGraph := range caseVariants(rootID) {
			t.Run("config_"+configName+"/graph_"+graphName, func(t *testing.T) {
				b, s, mp := getTestBackendWithUUIDClientID(t, configured)
				mp.lock.Lock()
				mp.applications["root-obj"] = fromGraph
				mp.lock.Unlock()
				passwordsBefore := len(mp.passwords)

				t.Run("role write", func(t *testing.T) {
					_, err := b.HandleRequest(context.Background(), &logical.Request{
						Operation: logical.CreateOperation,
						Path:      "roles/dyn",
						Data:      map[string]interface{}{"application_object_id": "root-obj"},
						Storage:   s,
					})
					assert.ErrorContains(t, err, msgTargetRootCredential)
				})

				t.Run("pre-existing role creds read", func(t *testing.T) {
					require.NoError(t, saveRole(context.Background(), s, &roleEntry{
						ApplicationObjectID: "root-obj",
						ApplicationID:       fromGraph,
						TTL:                 time.Hour,
					}, "stored"))

					resp, err := b.HandleRequest(context.Background(), &logical.Request{
						Operation: logical.ReadOperation,
						Path:      "creds/stored",
						Storage:   s,
					})
					require.NoError(t, err)
					require.NotNil(t, resp)
					require.True(t, resp.IsError(), "expected an error response, got %v", resp)
					assert.Contains(t, resp.Error().Error(), msgTargetRootCredential)
				})

				mp.lock.Lock()
				defer mp.lock.Unlock()
				assert.Equal(t, passwordsBefore, len(mp.passwords), "no password may be created")
			})
		}
	}
}

// TestRootCredentialTarget_DistinctUUIDAllowed verifies that the UUID-aware
// comparison does not block applications other than Vault's own.
func TestRootCredentialTarget_DistinctUUIDAllowed(t *testing.T) {
	b, s, mp := getTestBackendWithUUIDClientID(t, strings.ToUpper(generateUUID()))

	mp.lock.Lock()
	mp.applications["other-obj"] = generateUUID()
	mp.lock.Unlock()

	testRoleCreate(t, b, s, "other", map[string]interface{}{"application_object_id": "other-obj"})
}
