// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/rotation"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
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
	retBackend.settings = new(clientSettings)
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
