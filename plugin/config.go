package azuresecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
)

const (
	configPath = "config"
)

type azureConfig struct {
	SubscriptionID string        `json:"subscription_id"`
	TenantID       string        `json:"tenant_id"`
	ClientID       string        `json:"client_id"`
	ClientSecret   string        `json:"client_secret"`
	DefaultTTL     time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	Resource       string        `json:"resource"`
	Environment    string        `json:"environment"`
}

func (b *azureSecretBackend) getConfig(ctx context.Context, s logical.Storage) (*azureConfig, error) {
	config := new(azureConfig)
	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return config, nil
	}

	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *azureSecretBackend) saveConfig(ctx context.Context, cfg *azureConfig, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(configPath, cfg)
	if err != nil {
		return err
	}
	err = s.Put(ctx, entry)

	return nil
}
