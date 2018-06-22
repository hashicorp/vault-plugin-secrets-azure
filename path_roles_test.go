package azuresecrets

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestRoleCreate(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("SP role", func(t *testing.T) {
		spRole1 := map[string]interface{}{
			"roles": compactJSON(`[
		{
			"role_name": "Owner",
			"role_id": "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Owner",
			"scope":  "test_scope_1"
		},
		{
			"role_name": "Owner2",
			"role_id": "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Owner2",
			"scope":  "test_scope_2"
		}]`),
			"ttl":     int64(0),
			"max_ttl": int64(0),
		}

		spRole2 := map[string]interface{}{
			"roles": compactJSON(`[
		{
			"role_name": "Contributor",
			"role_id": "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor",
			"scope":  "test_scope_3"
		},
		{
			"role_name": "Contributor2",
			"role_id": "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor2",
			"scope":  "test_scope_3"
		}]`),
			"ttl":     int64(300),
			"max_ttl": int64(5000),
		}

		name := generateUUID()
		testRoleUpdate(t, b, s, name, spRole1)

		resp, err := testRoleRead(t, b, s, name)
		ok(t, err)

		resp.Data["roles"] = encodeJSON(resp.Data["roles"])
		equal(t, spRole1, resp.Data)

		testRoleUpdate(t, b, s, name, spRole2)

		resp, err = testRoleRead(t, b, s, name)
		ok(t, err)

		resp.Data["roles"] = encodeJSON(resp.Data["roles"])
		equal(t, spRole2, resp.Data)
	})

	t.Run("Optional role TTLs", func(t *testing.T) {
		testRole := map[string]interface{}{
			"roles": "[]",
		}

		name := generateUUID()
		testRoleUpdate(t, b, s, name, testRole)
		testRole["ttl"] = int64(0)
		testRole["max_ttl"] = int64(0)

		resp, err := testRoleRead(t, b, s, name)
		ok(t, err)
		resp.Data["roles"] = encodeJSON(resp.Data["roles"])
		equal(t, testRole, resp.Data)
	})

	t.Run("Role TTL Checks", func(t *testing.T) {
		b, s := getTestBackend(t, true)

		const skip = -999
		tests := []struct {
			ttl      int64
			max_ttl  int64
			expError bool
		}{
			{5, 10, false},
			{5, skip, false},
			{skip, 10, false},
			{-1, skip, true},
			{skip, -1, true},
			{-2, -1, true},
			{100, 100, false},
			{101, 100, true},
			{101, 0, false}, // max_ttl is unset so this is OK
		}

		for i, test := range tests {
			role := map[string]interface{}{
				"roles": "[]",
			}
			if test.ttl != skip {
				role["ttl"] = test.ttl
			}
			if test.max_ttl != skip {
				role["max_ttl"] = test.max_ttl
			}
			name := generateUUID()
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/" + name,
				Data:      role,
				Storage:   s,
			})
			ok(t, err)

			if resp.IsError() != test.expError {
				t.Fatalf("\ncase %d\nexp error: %t\ngot: %v", i, test.expError, err)
			}
		}
	})

	t.Run("Role name lookup", func(t *testing.T) {
		b, s := getTestBackend(t, true)
		var role = map[string]interface{}{
			"roles": compactJSON(`[
				{
					"role_name": "Owner",
					"role_id": "",
					"scope":  "test_scope_1"
				},
				{
					"role_name": "will be replaced",
					"role_id": "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor",
					"scope":  "test_scope_2"
				}
			]`),
		}

		name := generateUUID()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + name,
			Data:      role,
			Storage:   s,
		})
		ok(t, err)

		resp, err = testRoleRead(t, b, s, name)
		ok(t, err)
		roles := resp.Data["roles"].([]*azureRole)
		equal(t, "Owner", roles[0].RoleName)
		equal(t, "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Owner", roles[0].RoleID)
		equal(t, "Contributor", roles[1].RoleName)
		equal(t, "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor", roles[1].RoleID)
	})

}

func TestRoleCreateBad(t *testing.T) {
	b, s := getTestBackend(t, true)

	role := map[string]interface{}{}
	resp := testRoleUpdateBasic(t, b, s, "test_role_1", role)
	msg := "missing Azure role definitions"
	if !strings.Contains(resp.Error().Error(), msg) {
		t.Fatalf("expected to find: %s, got: %s", msg, resp.Error().Error())
	}

	role = map[string]interface{}{"roles": "asdf"}
	resp = testRoleUpdateBasic(t, b, s, "test_role_1", role)
	msg = "invalid Azure role definitions"
	if !strings.Contains(resp.Error().Error(), msg) {
		t.Fatalf("expected to find: %s, got: %s", msg, resp.Error().Error())
	}
}

func TestRoleList(t *testing.T) {
	b, s := getTestBackend(t, true)

	// Verify empty list
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	if resp.Data["keys"] != nil {
		t.Fatalf("expected nil, actual: %#v", resp.Data["keys"])
	}

	// Add some roles and verify the resulting list
	role := map[string]interface{}{
		"roles": "[]",
	}
	testRoleUpdate(t, b, s, "r1", role)
	testRoleUpdate(t, b, s, "r2", role)
	testRoleUpdate(t, b, s, "r3", role)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	exp := []string{"r1", "r2", "r3"}
	sort.Strings(resp.Data["keys"].([]string))
	if !reflect.DeepEqual(exp, resp.Data["keys"]) {
		t.Fatalf("expected %#v, actual %#v", exp, resp.Data["keys"])
	}

	// Delete a role and verify list is updated
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/r2",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	exp = []string{"r1", "r3"}
	sort.Strings(resp.Data["keys"].([]string))
	if !reflect.DeepEqual(exp, resp.Data["keys"]) {
		t.Fatalf("expected %#v, actual %#v", exp, resp.Data["keys"])
	}
}

func TestRoleDelete(t *testing.T) {
	b, s := getTestBackend(t, true)
	name := "test_role"
	nameAlt := "test_role_alt"

	role := map[string]interface{}{
		"roles": "[]",
	}

	// Create two roles and verify they're present
	testRoleUpdate(t, b, s, name, role)
	testRoleUpdate(t, b, s, nameAlt, role)

	// Delete one role and verify it is gone, and the other remains
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err)
	}

	resp, err = testRoleRead(t, b, s, name)
	if resp != nil || err != nil {
		t.Fatalf("expected nil response and error, actual:%#v and %#v", resp, err.Error())
	}

	resp, err = testRoleRead(t, b, s, nameAlt)
	if resp == nil {
		t.Fatalf("expected non-nil response, actual:%#v", resp)
	}
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	// Verify that delete against a missing role is a succesful no-op
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/not_a_role",
		Storage:   s,
	})
	if resp != nil || err != nil {
		t.Fatalf("expected nil response and error, actual:%#v and %#v", resp, err)
	}
}

// Utility function to create a role and fail on errors
func testRoleUpdate(t *testing.T, b *azureSecretBackend, s logical.Storage, name string, d map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

// Utility function to create a role while expecting and returning any errors
func testRoleUpdateBasic(t *testing.T, b *azureSecretBackend, s logical.Storage, name string, d map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	return resp
}

// Utility function to read a role and return any errors
func testRoleRead(t *testing.T, b *azureSecretBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Storage:   s,
	})
}
