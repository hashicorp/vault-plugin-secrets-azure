package azuresecrets

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

const (
	fakeSubscription = "ce7d1612-67c1-4dc6-8d81-4e0a432e696b"
	fakeRoleDef1     = "a527471d-5db9-4cbe-844d-97573d3e68a3"
	fakeRoleDef2     = "458f24bf-eaa3-42aa-a2ab-14e172d0bc5e"
)

var testRole = map[string]interface{}{
	"credential_type": SecretTypeSP,
	"roles": encodeJSON([]azureRole{
		azureRole{
			RoleName: "Owner",
			RoleID:   "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Owner",
			Scope:    "/subscriptions/ce7d1612-67c1-4dc6-8d81-4e0a432e696b",
		},
		azureRole{
			RoleName: "Contributor",
			RoleID:   "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor",
			Scope:    "/subscriptions/ce7d1612-67c1-4dc6-8d81-4e0a432e696b",
		},
	}),
}

func TestSPRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("Basic", func(t *testing.T) {
		name := generateUUID()
		testRoleUpdate(t, b, s, name, testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		ok(t, err)

		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		_, err = uuid.ParseUUID(resp.Data["client_id"].(string))
		ok(t, err)

		p := resp.Data["client_secret"].(string)
		if len(p) != passwordLength {
			t.Fatalf("expected password of length %d, got: %s", len(p), p)
		}

		equal(t, time.Duration(defaultTestTTL)*time.Second, resp.Secret.TTL)
		equal(t, time.Duration(defaultTestMaxTTL)*time.Second, resp.Secret.MaxTTL)
	})

	t.Run("TTLs", func(t *testing.T) {
		cfg := map[string]interface{}{
			"ttl":     5,
			"max_ttl": 10,
		}
		testConfigUpdate(t, b, s, cfg)

		name := generateUUID()
		testRoleUpdate(t, b, s, name, testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		ok(t, err)

		equal(t, 5*time.Second, resp.Secret.TTL)
		equal(t, 10*time.Second, resp.Secret.MaxTTL)

		roleUpdate := map[string]interface{}{
			"ttl":     20,
			"max_ttl": 30,
		}
		testRoleUpdate(t, b, s, name, roleUpdate)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		ok(t, err)

		equal(t, 20*time.Second, resp.Secret.TTL)
		equal(t, 30*time.Second, resp.Secret.MaxTTL)
	})
}

func TestSPRevoke(t *testing.T) {
	b, s := getTestBackend(t, true)

	testRoleUpdate(t, b, s, "test_role", testRole)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test_role",
		Storage:   s,
	})

	// Serialize and deserialize to lose typing as will really happen
	secret := new(logical.Secret)
	enc, err := jsonutil.EncodeJSON(resp.Secret)
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}
	jsonutil.DecodeJSON(enc, &secret)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    secret,
		Storage:   s,
	})

	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	if resp.IsError() {
		t.Fatalf("receive response error: %v", resp.Error())
	}
}

func TestSPReadMissingRole(t *testing.T) {
	b, s := getTestBackend(t, true)
	data := testRole

	testRoleUpdate(t, b, s, "test_role", data)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test_role_other",
		Storage:   s,
	})

	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	if !resp.IsError() {
		t.Fatal("expected a response error")
	}
}

func TestCredentialReadProviderError(t *testing.T) {
	b, s := getTestBackend(t, true)
	data := testRole

	testRoleUpdate(t, b, s, "test_role", data)

	mock := b.provider.(*mockProvider)
	mock.failCreateApplication = true

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test_role",
		Storage:   s,
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestCredentialInteg(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.SkipNow()
	}

	if os.Getenv("AZURE_CLIENT_SECRET") == "" {
		t.Skip("Azure Secrets: Azure environment variables not set. Skipping.")
	}

	b := Backend()
	s := new(logical.InmemStorage)
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
			MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
		},
		StorageView: s,
	}
	err := b.Setup(context.Background(), config)
	ok(t, err)

	// Add a Vault role that will provide creds with Azure "Reader" permissions
	rolename := "test_role"
	role := map[string]interface{}{
		"roles": fmt.Sprintf(`[{
			"role_name": "Reader",
			"scope":  "/subscriptions/%s"
		}]`, subscriptionID),
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roles/%s", rolename),
		Data:      role,
		Storage:   s,
	})
	ok(t, err)

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
	ok(t, err)

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Use the underlying provider to access clients directly for testing
	client := b.provider.(*azureProvider)
	spObjId := client._spObjId

	_, err = client.spClient.Get(context.Background(), spObjId)
	if err != nil {
		t.Fatalf("Expected nil error on GET of new SP, got: %#v", err)
	}

	// Verify that a role assignment was created. Get the assignment
	// info from Azure and verify it matches the Reader role.
	raIDs := resp.Secret.InternalData["roleAssignmentIDs"].([]string)
	equal(t, 1, len(raIDs))

	ra, err := client.raClient.GetByID(context.Background(), raIDs[0])
	ok(t, err)

	roleDefs, err := b.provider.ListRoles(context.Background(), fmt.Sprintf("subscriptions/%s", subscriptionID), "")
	ok(t, err)

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

	// Revoke the Service Principal by send back the secret we just
	// received, with a little type tweaking to make it work.
	resp.Secret.InternalData["roleAssignmentIDs"] = []interface{}{
		resp.Secret.InternalData["roleAssignmentIDs"].([]string)[0],
	}

	req := &logical.Request{
		Secret:  resp.Secret,
		Storage: s,
	}

	b.spRevoke(context.Background(), req, nil)

	// Verify that SP get is an error after delete. Expected there
	// to be a delay and that this step would take some time/retries,
	// but that seems not to be the case.
	_, err = client.spClient.Get(context.Background(), spObjId)

	if err == nil {
		t.Fatal("Expected error reading deleted SP")
	}
}
