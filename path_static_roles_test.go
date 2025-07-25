// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleName = "test-role"
	appObjID = "00000000-0000-0000-0000-000000000000"
)

// TestStaticRole_Create tests the creation of static roles in the Azure secrets backend.
// It uses a mocked backend to simulate the behavior of the Azure secrets backend.
// It validates the response for successful creation and checks for errors in invalid cases.
func TestStaticRole_Create(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	cases := []struct {
		name     string
		input    map[string]interface{}
		isErr    bool
		validate func(t *testing.T, resp *logical.Response)
	}{
		{
			name: "happy path",
			input: map[string]interface{}{
				paramApplicationObjectID: appObjID,
			},
			isErr: false,
		},
		{
			name:  "missing application_object_id",
			input: map[string]interface{}{},
			isErr: true,
			validate: func(t *testing.T, resp *logical.Response) {
				if resp == nil || !resp.IsError() {
					t.Errorf("expected error response for missing")
				}
			},
		},
	}

	for _, tc := range cases {
		name := "test-role-" + generateUUID()
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      pathStaticRole + name,
				Data:      tc.input,
				Storage:   s,
			})

			if tc.isErr {
				if err != nil {
					t.Logf("expected error: %v", err)
				} else if resp == nil || !resp.IsError() {
					t.Error("expected error but got success")
				}
			} else {
				assertRespNoError(t, resp, err)
			}

			if tc.validate != nil {
				tc.validate(t, resp)
			}
		})
	}
}

// TestStaticRole_Read tests reading static roles from the Azure secrets backend.
// It checks both existing and non-existing roles to ensure the backend behaves correctly.
func TestStaticRole_Read(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	testStaticRoleCreateHelper(t, b, s, roleName, appObjID)

	cases := []struct {
		name       string
		path       string
		wantExists bool
		wantValue  string
	}{
		{
			name:       "read existing",
			path:       pathStaticRole + roleName,
			wantExists: true,
			wantValue:  appObjID,
		},
		{
			name:       "read nonexistent",
			path:       pathStaticRole + "nonexistent-role",
			wantExists: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      tc.path,
				Storage:   s,
			})

			assertErrorIsNil(t, err)

			if tc.wantExists {
				if resp == nil || resp.Data == nil {
					t.Fatal("expected data, got nil")
				}
				got := resp.Data[paramApplicationObjectID]
				if got != tc.wantValue {
					t.Errorf("expected %s, got %v", tc.wantValue, got)
				}
			} else {
				if resp != nil && resp.Data != nil {
					t.Errorf("expected nil, got %v", resp.Data)
				}
			}
		})
	}
}

// TestStaticRole_Update tests updating static roles in the Azure secrets backend.
// It verifies that updates are applied correctly and that the backend handles errors as expected.
func TestStaticRole_Update(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	testStaticRoleCreateHelper(t, b, s, roleName, appObjID)

	cases := []struct {
		name      string
		input     map[string]interface{}
		expectErr bool
		expected  string
	}{
		{
			name: "valid update to application_object_id",
			input: map[string]interface{}{
				paramApplicationObjectID: "00000000-0000-0000-0000-000000000001",
			},
			expectErr: false,
			expected:  "00000000-0000-0000-0000-000000000001",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      pathStaticRole + roleName,
				Data:      tc.input,
				Storage:   s,
			})

			if tc.expectErr {
				if resp == nil || !resp.IsError() {
					t.Fatal("expected error, got none")
				}
				return
			}

			assertRespNoError(t, resp, err)

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      pathStaticRole + roleName,
				Storage:   s,
			})
			assertRespNoError(t, resp, err)

			got := resp.Data[paramApplicationObjectID]
			if got != tc.expected {
				t.Errorf("expected %s, got %v", tc.expected, got)
			}
		})
	}
}

// TestStaticRole_Delete tests the deletion of static roles in the Azure secrets backend.
// It checks both successful deletions and attempts to delete non-existing roles.
func TestStaticRole_Delete(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	testStaticRoleCreateHelper(t, b, s, roleName, appObjID)

	t.Run("delete existing", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      pathStaticRole + roleName,
			Storage:   s,
		})
		assertErrorIsNil(t, err)
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error())
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      pathStaticRole + roleName,
			Storage:   s,
		})
		assertErrorIsNil(t, err)
		if resp != nil && resp.Data != nil {
			t.Errorf("expected nil data after delete, got: %v", resp.Data)
		}
	})

	t.Run("delete nonexistent", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      pathStaticRole + roleName,
			Storage:   s,
		})
		assertErrorIsNil(t, err)
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error deleting nonexistent role: %v", resp.Error())
		}
	})
}

// testStaticRoleCreateHelper is a helper function to create a static role in the Azure secrets backend.
func testStaticRoleCreateHelper(t *testing.T, b *azureSecretBackend, s logical.Storage, name, appID string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      pathStaticRole + name,
		Data: map[string]interface{}{
			paramApplicationObjectID: appID,
		},
		Storage: s,
	})
	assertRespNoError(t, resp, err)
}
