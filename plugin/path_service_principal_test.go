package azuresecrets

import (
	"context"
	"testing"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
)

const (
	fakeSubscription = "ce7d1612-67c1-4dc6-8d81-4e0a432e696b"
	fakeRoleDef1     = "a527471d-5db9-4cbe-844d-97573d3e68a3"
	fakeRoleDef2     = "458f24bf-eaa3-42aa-a2ab-14e172d0bc5e"
)

var testRole = map[string]interface{}{
	"credential_type": SecretTypeSP,
	"roles": encode([]azureRole{
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
		name := newUUID()
		testRoleCreate(t, b, s, name, testRole)

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

		name := newUUID()
		testRoleCreate(t, b, s, name, testRole)

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
		testRoleCreate(t, b, s, name, roleUpdate)

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

	testRoleCreate(t, b, s, "test_role", testRole)

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

	testRoleCreate(t, b, s, "test_role", data)

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

	testRoleCreate(t, b, s, "test_role", data)

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
