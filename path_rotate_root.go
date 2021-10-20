package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func pathRotateRoot(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRoot,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},

		HelpSynopsis: "Attempt to rotate the root credentials used to communicate with Azure.",
		HelpDescription: "This path will attempt to generate new root credentials for the user used to access and manipulate Azure.\n" +
			"The new credentials will not be returned from this endpoint, nor the read config endpoint.",
	}
}

func (b *azureSecretBackend) pathRotateRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	expDur := config.RootPasswordExpiration
	if expDur == 0 {
		expDur = defaultRootPasswordExpiration
	}
	expiration := time.Now().Add(expDur)

	passCred, err := b.rotateRootCredentials(ctx, req.Storage, *config, expiration)
	if err != nil {
		return nil, err
	}

	resultData := map[string]interface{}{
		"secret_id": *passCred.KeyID,
		"end_date":  *passCred.EndDate,
	}
	if passCred.DisplayName != nil && *passCred.DisplayName != "" {
		resultData["display_name"] = *passCred.DisplayName
	}

	resp := &logical.Response{
		Data: resultData,
	}

	return addAADWarning(resp, config), nil
}

func (b *azureSecretBackend) rotateRootCredentials(ctx context.Context, storage logical.Storage, cfg azureConfig, expiration time.Time) (cred api.PasswordCredential, err error) {
	client, err := b.getClient(ctx, storage)
	if err != nil {
		return api.PasswordCredential{}, err
	}

	// We need to use List instead of Get here because we don't have the Object ID
	// (which is different from the Application/Client ID)
	apps, err := client.provider.ListApplications(ctx, fmt.Sprintf("appId eq '%s'", cfg.ClientID))
	if err != nil {
		return api.PasswordCredential{}, err
	}

	if len(apps) == 0 {
		return api.PasswordCredential{}, fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return api.PasswordCredential{}, fmt.Errorf("multiple applications found - double check your client_id")
	}

	app := apps[0]

	// Get a list of the current passwords to delete if adding a new credential succeeds. This list will not
	// include the ID of the new password created via AddApplicationPassword
	credsToDelete := []string{}
	for _, cred := range app.PasswordCredentials {
		credsToDelete = append(credsToDelete, *cred.KeyID)
	}

	uniqueID, err := uuid.GenerateUUID()
	if err != nil {
		return api.PasswordCredential{}, fmt.Errorf("failed to generate UUID: %w", err)
	}

	// This could have the same username customization logic put on it if we really wanted it here
	passwordDisplayName := fmt.Sprintf("vault-%s", uniqueID)

	newPasswordResp, err := client.provider.AddApplicationPassword(ctx, *app.ID, passwordDisplayName, expiration)
	if err != nil {
		return api.PasswordCredential{}, fmt.Errorf("failed to add new password: %w", err)
	}

	// Write a WAL with the new credential (and some other info) to write to the config later
	// This is done because the new credential is typically not available to use IMMEDIATELY
	// after creating it. This can create errors for callers so instead this will write
	// the config and clean up old keys asynchronously after ~10m (backend.WALRollbackMinAge)
	// This also will automatically retry because of the standard WAL behavior
	wal := rotateCredsWAL{
		AppID:          *app.ID,
		NewSecret:      *newPasswordResp.PasswordCredential.SecretText,
		KeyIDsToRemove: credsToDelete,
		Expiration:     time.Now().Add(walRotateRootCredsExpiration),
	}

	_, walErr := framework.PutWAL(ctx, storage, walRotateRootCreds, wal)
	if walErr != nil {
		// Remove the key since we failed to save the WAL to Vault storage. It's reasonable to assume that this call
		// to Azure will succeed since the AddApplicationPassword call succeeded above. If it doesn't, we aren't going
		// to do any retries via a WAL here since the current configuration will continue to work.
		azureErr := client.provider.RemoveApplicationPassword(ctx, *app.ID, *newPasswordResp.PasswordCredential.KeyID)
		merr := multierror.Append(err, azureErr)
		return api.PasswordCredential{}, merr
	}

	return newPasswordResp.PasswordCredential, nil
}

const walRotateRootCreds = "rotateRootCreds"
const walRotateRootCredsExpiration = 24 * time.Hour

type rotateCredsWAL struct {
	AppID          string
	OldSecret      string
	NewSecret      string
	KeyIDsToRemove []string
	Expiration     time.Time
}

type passwordRemover interface {
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

func removeApplicationPasswords(ctx context.Context, passRemover passwordRemover, appID string, passwordKeyIDs ...string) (err error) {
	merr := new(multierror.Error)
	var remainingCreds []string
	for _, keyID := range passwordKeyIDs {
		// Attempt to remove all of them, don't fail early
		err := passRemover.RemoveApplicationPassword(ctx, appID, keyID)
		if err != nil {
			merr = multierror.Append(merr, err)
			remainingCreds = append(remainingCreds, keyID)
		}
	}

	return merr.ErrorOrNil()
}

func (b *azureSecretBackend) rotateRootCredsWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	entry := rotateCredsWAL{}

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	if time.Now().After(entry.Expiration) {
		b.Logger().Info("WAL for removing dangling credentials for root user has expired")
		return nil
	}

	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	cfg.ClientSecret = entry.NewSecret

	err = b.saveConfig(ctx, cfg, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to save new configuration: %w", err)
	}

	// b.saveConfig does a reset so this should get a new client with the updated creds
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	app, err := client.provider.GetApplication(ctx, entry.AppID)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing application: %w", err)
	}

	actualKeys := []string{}
	for _, pc := range app.PasswordCredentials {
		actualKeys = append(actualKeys, *pc.KeyID)
	}
	keysToRemove := intersectStrings(entry.KeyIDsToRemove, actualKeys)
	if len(keysToRemove) == 0 {
		return nil
	}

	b.Logger().Debug("Attempting to remove dangling credentials for root user")

	err = removeApplicationPasswords(ctx, client.provider, entry.AppID, keysToRemove...)
	if err != nil {
		return err
	}
	b.Logger().Debug("Successfully removed dangling credentials for root user")
	return nil
}

func intersectStrings(a []string, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}

	aMap := map[string]struct{}{}
	for _, aStr := range a {
		aMap[aStr] = struct{}{}
	}

	result := []string{}
	for _, bStr := range b {
		if _, exists := aMap[bStr]; exists {
			result = append(result, bStr)
		}
	}
	return result
}
