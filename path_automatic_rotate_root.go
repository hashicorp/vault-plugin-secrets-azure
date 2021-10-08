package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/ticker"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rotateRootConfigPath = "rotate_root_config"
)

type rotateRootConfig struct {
	RootRotationCadence    time.Duration `json:"cadence"`
	RootRotationExpiration time.Duration `json:"expiration"`
	NextRootRotationTime   time.Time     `json:"next_rotation_time"`
}

func pathRotateRootConfig(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		// TODO: I don't really like this endpoint, so consider renaming it
		Pattern: "rotate-root/automatic",
		Fields: map[string]*framework.FieldSchema{
			"cadence": {
				Type:     framework.TypeString,
				Required: false,
				Description: "How often the root credentials should be rotated automatically. " +
					"If 0, this will disable automatic rotation. This can be either a number " +
					"of seconds or a time formatted duration (ex: 24h)",
			},
			"expiration": {
				Type: framework.TypeString,
				// 28 weeks (~6 months) -> days -> hours
				Default: (28 * 7 * 24 * time.Hour).String(),
				Description: "The expiration date of the new credentials in Azure. This can be either a number of " +
					"seconds or a time formatted duration (ex: 24h)",
				Required: false,
			},
			"rotate_now": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Rotates the root credentials immediately when saving the automatic rotation config",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.pathWriteRotateRootConfig,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathWriteRotateRootConfig,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathReadRotateRootConfig,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback:                    b.pathDeleteRotateRootConfig,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},
	}
}

func (b *azureSecretBackend) pathWriteRotateRootConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate the arguments

	// Retrieve the existing config (if one exists) and merge the new arguments

	// Save the config

	// Update ticker

	// Rotate the credentials (if argument set)
}

func (b *azureSecretBackend) pathReadRotateRootConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getRotateRootConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config: %w", err)
	}

	if cfg == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"cadence":            cfg.RootRotationCadence.String(),
			"expiration":         cfg.RootRotationExpiration.String(),
			"next_rotation_time": cfg.NextRootRotationTime,
		},
	}

	return resp, nil
}

func (b *azureSecretBackend) pathDeleteRotateRootConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, rotateRootConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to delete config: %w", err)
	}

	b.ticker.Stop(rootCredTickerID)
	return nil, nil
}

func getRotateRootConfig(ctx context.Context, s logical.Storage) (*rotateRootConfig, error) {
	entry, err := s.Get(ctx, rotateRootConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rotate-root config from storage: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	cfg := &rotateRootConfig{}
	err = entry.DecodeJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	return cfg, nil
}

func writeRotateRootConfig(ctx context.Context, s logical.Storage, cfg *rotateRootConfig) error {
	entry, err := logical.StorageEntryJSON(rotateRootConfigPath, cfg)
	if err != nil {
		return fmt.Errorf("failed creating storage entry: %w", err)
	}
	err = s.Put(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to write rotate-root config: %w", err)
	}
	return nil
}

func (b *azureSecretBackend) automaticRotateRootFunc(storage logical.Storage) ticker.RunFunc {
	return func(ctx context.Context, logger hclog.Logger, runnerDetails ticker.RunnerDetails) error {
		cfg, err := getRotateRootConfig(ctx, storage)
		if err != nil {
			return fmt.Errorf("failed to retrieve configuration from storage: %w", err)
		}

		expiration := time.Now().Add(cfg.RootRotationExpiration)

		passCred, warnings, err := b.rotateRootCredentials(ctx, storage, expiration)
		if err != nil {
			return fmt.Errorf("failed to automatically rotate root credential: %w", err)
		}

		if len(warnings) > 0 {
			b.Logger().Warn("Root credential has been successfully rotated, but had warnings",
				"displayName", passCred.DisplayName,
				"expiration", passCred.EndDate,
				"warnings", warnings,
			)
		} else {
			b.Logger().Info("Root credential has been successfully rotated",
				"displayName", passCred.DisplayName,
				"expiration", passCred.EndDate,
			)
		}

		cfg.NextRootRotationTime = runnerDetails.NextRun
		err = writeRotateRootConfig(ctx, storage, cfg)
		if err != nil {
			b.Logger().Error("Next root credential time failed to save", "error", err)
		}

		return nil
	}
}
