package azuresecrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

var (
	testRole = map[string]interface{}{
		"azure_roles": encodeJSON([]AzureRole{
			{
				RoleName: "Owner",
				RoleID:   "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Owner",
				Scope:    "/subscriptions/ce7d1612-67c1-4dc6-8d81-4e0a432e696b",
			},
			{
				RoleName: "Contributor",
				RoleID:   "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor",
				Scope:    "/subscriptions/ce7d1612-67c1-4dc6-8d81-4e0a432e696b",
			},
		}),
	}

	testGroupRole = map[string]interface{}{
		"azure_groups": encodeJSON([]AzureGroup{
			{
				GroupName: "foo",
				ObjectID:  "00000000-1111-2222-3333-444444444444FAKE_GROUP-foo",
			},
			{
				GroupName: "baz",
				ObjectID:  "00000000-1111-2222-3333-444444444444FAKE_GROUP-baz",
			},
		}),
	}

	testStaticSPRole = map[string]interface{}{
		"application_object_id": "00000000-0000-0000-0000-000000000000",
	}
)

// TestSP_WAL_Cleanup tests that any Service Principal that gets created, but
// fails to have roles associated with it, gets cleaned up by the periodic WAL
// function.
func TestSP_WAL_Cleanup(t *testing.T) {
	b, s := getTestBackend(t, true)

	// overwrite the normal test backend provider with the errMockProvider
	errMockProvider := newErrMockProvider()
	b.getProvider = func(s *clientSettings, useMsGraphApi bool, p passwords) (AzureProvider, error) {
		return errMockProvider, nil
	}

	// verify basic cred issuance
	t.Run("Role assign fail", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testRole)

		// create a short timeout to short-circuit the retry process and trigger the
		// deadline error
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("expected deadline error, but got '%s'", err.Error())
		}
		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		assertEmptyWAL(t, b, errMockProvider, s)
	})
}

func assertEmptyWAL(t *testing.T, b *azureSecretBackend, emp AzureProvider, s logical.Storage) {
	t.Helper()

	wal, err := framework.ListWAL(context.Background(), s)
	if err != nil {
		t.Fatalf("error listing wal: %s", err)
	}
	req := &logical.Request{
		Storage: s,
	}

	// loop of WAL entries and trigger the rollback method for each, simulating
	// Vault's rollback mechanism
	for _, v := range wal {
		ctx := context.Background()
		entry, err := framework.GetWAL(ctx, s, v)
		if err != nil {
			t.Fatal(err)
		}

		// Decode the WAL data
		var app walApp
		d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
			Result:     &app,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = d.Decode(entry.Data)
		if err != nil {
			t.Fatal(err)
		}

		_, err = emp.GetApplication(context.Background(), app.AppObjID)
		if err != nil {
			t.Fatalf("expected to find application (%s), but wasn't found", app.AppObjID)
		}

		err = b.walRollback(ctx, req, entry.Kind, entry.Data)
		if err != nil {
			t.Fatal(err)
		}
		if err := framework.DeleteWAL(ctx, s, v); err != nil {
			t.Fatal(err)
		}

		_, err = emp.GetApplication(context.Background(), app.AppObjID)
		if err == nil {
			t.Fatalf("expected error getting application")
		}
	}
}

func TestSPRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	// verify basic cred issuance
	t.Run("Basic Role", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		// verify client_id format, and that the corresponding app actually exists
		_, err = uuid.ParseUUID(resp.Data["client_id"].(string))
		assertErrorIsNil(t, err)

		appObjID := resp.Secret.InternalData["app_object_id"].(string)
		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)

		if !client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application was not created")
		}

		assertClientSecret(t, resp.Data)
	})

	// verify basic cred issuance using group membership
	t.Run("Basic Group", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testGroupRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		// verify client_id format, and that the corresponding app actually exists
		_, err = uuid.ParseUUID(resp.Data["client_id"].(string))
		assertErrorIsNil(t, err)

		appObjID := resp.Secret.InternalData["app_object_id"].(string)
		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)

		if !client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application was not created")
		}

		assertClientSecret(t, resp.Data)
	})

	// verify role TTLs are reflected in secret
	t.Run("TTLs", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		equal(t, 0*time.Second, resp.Secret.TTL)
		equal(t, 0*time.Second, resp.Secret.MaxTTL)

		roleUpdate := map[string]interface{}{
			"ttl":     20,
			"max_ttl": 30,
		}
		testRoleCreate(t, b, s, name, roleUpdate)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		equal(t, 20*time.Second, resp.Secret.TTL)
		equal(t, 30*time.Second, resp.Secret.MaxTTL)
	})
}

func TestStaticSPRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	// verify basic cred issuance
	t.Run("Basic", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testStaticSPRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		// verify client_id format, and that the corresponding app actually exists
		_, err = uuid.ParseUUID(resp.Data["client_id"].(string))
		assertErrorIsNil(t, err)

		keyID := resp.Secret.InternalData["key_id"].(string)
		if len(keyID) == 0 {
			t.Fatalf("expected keyId to not be empty")
		}

		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)

		if !client.provider.(*mockProvider).passwordExists(keyID) {
			t.Fatalf("password was not created")
		}

		assertClientSecret(t, resp.Data)
	})

	// verify role TTLs are reflected in secret
	t.Run("TTLs", func(t *testing.T) {
		name := generateUUID()
		testRoleCreate(t, b, s, name, testStaticSPRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		equal(t, 0*time.Second, resp.Secret.TTL)
		equal(t, 0*time.Second, resp.Secret.MaxTTL)

		roleUpdate := map[string]interface{}{
			"ttl":     20,
			"max_ttl": 30,
		}
		testRoleCreate(t, b, s, name, roleUpdate)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		equal(t, 20*time.Second, resp.Secret.TTL)
		equal(t, 30*time.Second, resp.Secret.MaxTTL)
	})
}

func TestSPRevoke(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("roles", func(t *testing.T) {
		testRoleCreate(t, b, s, "test_role", testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/test_role",
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		appObjID := resp.Secret.InternalData["app_object_id"].(string)
		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)

		if !client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application was not created")
		}

		// Serialize and deserialize the secret to remove typing, as will really happen.
		fakeSaveLoad(resp.Secret)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation,
			Secret:    resp.Secret,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("receive response error: %v", resp.Error())
		}

		if client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application present but should have been deleted")
		}
	})

	t.Run("groups", func(t *testing.T) {
		testRoleCreate(t, b, s, "test_role", testGroupRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/test_role",
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		appObjID := resp.Secret.InternalData["app_object_id"].(string)
		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)

		if !client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application was not created")
		}

		// Serialize and deserialize the secret to remove typing, as will really happen.
		fakeSaveLoad(resp.Secret)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation,
			Secret:    resp.Secret,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("receive response error: %v", resp.Error())
		}

		if client.provider.(*mockProvider).appExists(appObjID) {
			t.Fatalf("application present but should have been deleted")
		}
	})
}

func TestStaticSPRevoke(t *testing.T) {
	b, s := getTestBackend(t, true)

	testRoleCreate(t, b, s, "test_role", testStaticSPRole)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test_role",
		Storage:   s,
	})
	assertErrorIsNil(t, err)

	keyID := resp.Secret.InternalData["key_id"].(string)
	if len(keyID) == 0 {
		t.Fatalf("expected keyId to not be empty")
	}

	client, err := b.getClient(context.Background(), s)
	assertErrorIsNil(t, err)

	if !client.provider.(*mockProvider).passwordExists(keyID) {
		t.Fatalf("password was not created")
	}

	// Serialize and deserialize the secret to remove typing, as will really happen.
	fakeSaveLoad(resp.Secret)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    resp.Secret,
		Storage:   s,
	})

	assertErrorIsNil(t, err)

	if resp.IsError() {
		t.Fatalf("receive response error: %v", resp.Error())
	}

	if client.provider.(*mockProvider).passwordExists(keyID) {
		t.Fatalf("password present but should have been deleted")
	}
}

func TestSPReadMissingRole(t *testing.T) {
	b, s := getTestBackend(t, true)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/some_role_that_doesnt_exist",
		Storage:   s,
	})

	assertErrorIsNil(t, err)

	if !resp.IsError() {
		t.Fatal("expected a response error")
	}
}

func TestCredentialReadProviderError(t *testing.T) {
	b, s := getTestBackend(t, true)

	testRoleCreate(t, b, s, "test_role", testRole)

	client, err := b.getClient(context.Background(), s)
	assertErrorIsNil(t, err)
	client.provider.(*mockProvider).failNextCreateApplication = true

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test_role",
		Storage:   s,
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestCredentialInteg is an integration test against the live Azure service. It requires
// valid, sufficiently-privileged Azure credentials in env variables.
func TestCredentialInteg(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.SkipNow()
	}

	if os.Getenv("AZURE_CLIENT_SECRET") == "" {
		t.Skip("Azure Secrets: Azure environment variables not set. Skipping.")
	}

	t.Run("SP", func(t *testing.T) {
		t.Parallel()

		b := backend()
		s := new(logical.InmemStorage)
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")

		config := &logical.BackendConfig{
			Logger: logging.NewVaultLogger(log.Trace),
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: defaultLeaseTTLHr,
				MaxLeaseTTLVal:     maxLeaseTTLHr,
			},
			StorageView: s,
		}
		err := b.Setup(context.Background(), config)
		assertErrorIsNil(t, err)

		// Add a Vault role that will provide creds with Azure "Reader" permissions
		// Resources groups "vault-azure-secrets-test1" and "vault-azure-secrets-test2"
		// should already exist in the test infrastructure. (The test can be simplified
		// to just use scope "/subscriptions/%s" if need be.)
		rolename := "test_role"
		role := map[string]interface{}{
			"azure_roles": fmt.Sprintf(`[
			{
				"role_name": "Reader",
				"scope":  "/subscriptions/%s/resourceGroups/vault-azure-secrets-test1"
			},
			{
				"role_name": "Reader",
				"scope":  "/subscriptions/%s/resourceGroups/vault-azure-secrets-test2"
			}]`, subscriptionID, subscriptionID),
		}
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("roles/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		// Request credentials
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("creds/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		appID := resp.Data["client_id"].(string)

		// Use the underlying provider to access clients directly for testing
		client, err := b.getClient(context.Background(), s)
		assertErrorIsNil(t, err)
		provider := client.provider.(*provider)

		// recover the SP Object ID, which is not used by the application but
		// is helpful for verification testing
		spList, err := provider.spClient.List(context.Background(), "")
		assertErrorIsNil(t, err)

		var spObjID string
		for spList.NotDone() {
			for _, v := range spList.Values() {
				if to.String(v.AppID) == appID {
					spObjID = to.String(v.ObjectID)
					goto FOUND
				}
			}
			spList.Next()
		}
		t.Fatal("Couldn't find SP Object ID")

	FOUND:
		// verify the new SP can be accessed
		_, err = provider.spClient.Get(context.Background(), spObjID)
		if err != nil {
			t.Fatalf("Expected nil error on GET of new SP, got: %#v", err)
		}

		// Verify that the role assignments were created. Get the assignment
		// info from Azure and verify it matches the Reader role.
		raIDs := resp.Secret.InternalData["role_assignment_ids"].([]string)
		equal(t, 2, len(raIDs))

		ra, err := provider.raClient.GetByID(context.Background(), raIDs[0])
		assertErrorIsNil(t, err)

		roleDefs, err := client.provider.ListRoles(context.Background(), fmt.Sprintf("subscriptions/%s", subscriptionID), "")
		assertErrorIsNil(t, err)

		defID := *ra.RoleAssignmentPropertiesWithScope.RoleDefinitionID
		found := false
		for _, def := range roleDefs {
			if *def.ID == defID && *def.RoleName == "Reader" {
				found = true
				break
			}
		}

		if !found {
			t.Fatal("'Reader' role assignment not found")
		}

		// Serialize and deserialize the secret to remove typing, as will really happen.
		fakeSaveLoad(resp.Secret)

		// Revoke the Service Principal by sending back the secret we just received
		req := &logical.Request{
			Secret:  resp.Secret,
			Storage: s,
		}

		b.spRevoke(context.Background(), req, nil)

		// Verify that SP get is an error after delete. Expected there
		// to be a delay and that this step would take some time/retries,
		// but that seems not to be the case.
		_, err = provider.spClient.Get(context.Background(), spObjID)

		if err == nil {
			t.Fatal("Expected error reading deleted SP")
		}
	})

	t.Run("Static SP", func(t *testing.T) {
		t.Parallel()

		b := backend()
		s := new(logical.InmemStorage)

		config := &logical.BackendConfig{
			Logger: logging.NewVaultLogger(log.Trace),
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: defaultLeaseTTLHr,
				MaxLeaseTTLVal:     maxLeaseTTLHr,
			},
			StorageView: s,
		}
		err := b.Setup(context.Background(), config)
		assertErrorIsNil(t, err)

		// Add a Vault role that will provide creds with Azure "Reader" permissions
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")

		rolename := "test_role"
		role := map[string]interface{}{
			"azure_roles": fmt.Sprintf(`[{
			"role_name": "Reader",
			"scope":  "/subscriptions/%s"
		}]`, subscriptionID),
		}
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("roles/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		// Request credentials
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("creds/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		origResp := resp

		appObjID := resp.Secret.InternalData["app_object_id"].(string)
		appID := resp.Data["client_id"].(string)

		// Create a new role that will add passwords to the previously
		// created application when creds are requested.

		rolename = "test_role2"
		role = map[string]interface{}{
			"application_object_id": appObjID,
		}
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("roles/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		// Request credentials
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("creds/%s", rolename),
			Data:      role,
			Storage:   s,
		})
		assertErrorIsNil(t, err)

		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}

		// Test the added password by creating a new Azure provider with these
		// creds and attempting an operation with it.
		clientConfig := azureConfig{}

		settings, err := b.getClientSettings(context.Background(), &clientConfig)
		if err != nil {
			t.Fatal(err)
		}

		settings.ClientID = appID
		settings.ClientSecret = resp.Data["client_secret"].(string)

		success := false

		// The new app may not be propagated immediately, so retry for ~30s.
		for i := 0; i < 8; i++ {
			// New credentials are only tested during an actual operation, not provider creation.
			// This step should never fail.
			p, err := newAzureProvider(settings, true, passwords{})
			if err != nil {
				t.Fatal(err)
			}

			_, err = p.GetApplication(context.Background(), appObjID)
			if err == nil {
				success = true
				break
			}
			time.Sleep(5 * time.Second)
		}

		if !success {
			t.Fatalf("unable to validate with credentials. Last error: %v", err)
		}

		// Serialize and deserialize the secret to remove typing, as will really happen.
		fakeSaveLoad(origResp.Secret)

		// Revoke the Service Principal by sending back the secret we just received
		req := &logical.Request{
			Secret:  origResp.Secret,
			Storage: s,
		}

		_, err = b.spRevoke(context.Background(), req, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func assertClientSecret(tb testing.TB, data map[string]interface{}) {
	assertKeyExists(tb, data, "client_secret")
	actualPassword, ok := data["client_secret"].(string)
	if !ok {
		tb.Fatalf("client_secret is not a string")
	}
	if len(actualPassword) != passwordLength {
		tb.Fatalf("client_secret is not the correct length: expected %d but was %d", passwordLength, len(actualPassword))
	}
}
