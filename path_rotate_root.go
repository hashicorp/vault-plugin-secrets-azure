package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func pathRotateRoot(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Fields: map[string]*framework.FieldSchema{
			"expiration": {
				Type: framework.TypeString,
				// 28 weeks (~6 months) -> days -> hours
				Default:     (28 * 7 * 24 * time.Hour).String(),
				Description: "The expiration date of the new credentials in Azure. This can be either a number of seconds or a time formatted duration (ex: 24h)",
				Required:    false,
			},
		},
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
	expirationDur, err := parseutil.ParseDurationSecond(data.Get("expiration").(string))
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}
	expiration := time.Now().Add(expirationDur)

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	passCred, warnings, err := b.rotateRootCredentials(ctx, req.Storage, *config, expiration)
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
		Data:     resultData,
		Warnings: warnings,
	}

	return addAADWarning(resp, config), nil
}

func (b *azureSecretBackend) rotateRootCredentials(ctx context.Context, storage logical.Storage, cfg azureConfig, expiration time.Time) (cred api.PasswordCredential, warnings []string, err error) {
	client, err := b.getClient(ctx, storage)
	if err != nil {
		return api.PasswordCredential{}, nil, err
	}

	// We need to use List instead of Get here because we don't have the Object ID
	// (which is different from the Application/Client ID)
	apps, err := client.provider.ListApplications(ctx, fmt.Sprintf("appId eq '%s'", cfg.ClientID))
	if err != nil {
		return api.PasswordCredential{}, nil, err
	}

	if len(apps) == 0 {
		return api.PasswordCredential{}, nil, fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return api.PasswordCredential{}, nil, fmt.Errorf("multiple applications found - double check your client_id")
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
		return api.PasswordCredential{}, nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	// This could have the same username customization logic put on it if we really wanted it here
	passwordDisplayName := fmt.Sprintf("vault-%s", uniqueID)

	newPasswordResp, err := client.provider.AddApplicationPassword(ctx, *app.ID, passwordDisplayName, expiration)
	if err != nil {
		return api.PasswordCredential{}, nil, fmt.Errorf("failed to add new password: %w", err)
	}

	cfg.ClientSecret = *newPasswordResp.PasswordCredential.SecretText

	err = b.saveConfig(ctx, &cfg, storage)
	if err != nil {
		// Remove the key since we failed to save it to Vault storage. It's reasonable to assume that this call
		// to Azure will succeed since the AddApplicationPassword call succeeded above. If it doesn't, we aren't going
		// to do any retries via a WAL here since the current configuration will continue to work.
		azureErr := client.provider.RemoveApplicationPassword(ctx, *app.ID, *newPasswordResp.PasswordCredential.KeyID)
		merr := multierror.Append(err, azureErr)
		return api.PasswordCredential{}, nil, merr
	}

	err = removeApplicationPasswords(ctx, storage, client.provider, *app.ID, credsToDelete...)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to clean up all other credentials for root user. Will attempt again later.\n%s", err.Error()))
	}

	return newPasswordResp.PasswordCredential, warnings, nil
}

const walRemoveCreds = "removeCreds"
const walRemoveCredsExpiration = 24 * time.Hour

type removeCredsWAL struct {
	AppID          string
	KeyIDsToRemove []string
	Expiration     time.Time
}

type passwordRemover interface {
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

func removeApplicationPasswords(ctx context.Context, storage logical.Storage, passRemover passwordRemover, appID string, passwordKeyIDs ...string) (err error) {
	wal := removeCredsWAL{
		AppID:          appID,
		KeyIDsToRemove: passwordKeyIDs,
		Expiration:     time.Now().Add(walRemoveCredsExpiration),
	}
	walID, walErr := framework.PutWAL(ctx, storage, walRemoveCreds, wal)

	// If writing the WAL failed, continue to try to remove the creds from Azure and report the WAL error later if
	// the removal failed
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

	if len(remainingCreds) == 0 {
		// If walErr != nil we failed to write the WAL in the first place, so we don't need to remove it
		if walErr == nil {
			err := framework.DeleteWAL(ctx, storage, walID)
			if err != nil {
				return fmt.Errorf("passwords removed, but WAL failed to be removed: %w", err)
			}
		}
		return nil
	}

	return merr.ErrorOrNil()
}

func (b *azureSecretBackend) rollbackCredsWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	entry := removeCredsWAL{}

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

	merr := new(multierror.Error)
	for _, keyID := range keysToRemove {
		// Attempt to remove all of them, don't fail early
		err := client.provider.RemoveApplicationPassword(ctx, entry.AppID, keyID)
		if err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	return merr.ErrorOrNil()
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
			continue
		}
	}
	return result
}
