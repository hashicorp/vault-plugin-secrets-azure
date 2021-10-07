package azuresecrets

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/date"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
)

func TestRotateRootCredentials(t *testing.T) {
	type testCase struct {
		rawConfig map[string]interface{}
	}

	tests := map[string]testCase{
		"AAD": {
			rawConfig: map[string]interface{}{
				"subscription_id": generateUUID(),
				"tenant_id":       generateUUID(),
				"client_id":       testClientID,
				"client_secret":   testClientSecret,
				"environment":     "AZURECHINACLOUD",
				"ttl":             defaultTestTTL,
				"max_ttl":         defaultTestMaxTTL,
			},
		},
		"MS-Graph": {
			rawConfig: map[string]interface{}{
				"subscription_id":         generateUUID(),
				"tenant_id":               generateUUID(),
				"client_id":               testClientID,
				"client_secret":           testClientSecret,
				"environment":             "AZURECHINACLOUD",
				"ttl":                     defaultTestTTL,
				"max_ttl":                 defaultTestMaxTTL,
				"use_microsoft_graph_api": true,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			b, storage := getTestBackend(t, false)
			testConfigCreate(t, b, storage, test.rawConfig)

			ctx := context.Background()

			originalCfg, err := b.getConfig(ctx, storage)
			assertErrorIsNil(t, err)

			now := time.Now()

			objID := "test-client-uuid"
			keyID := "original-credential"

			apps := []api.ApplicationResult{
				{
					AppID: &testClientID,
					ID:    &objID,
					PasswordCredentials: []*api.PasswordCredential{
						{
							DisplayName: strPtr("test-credential-01"),
							StartDate:   &date.Time{now.Add(-1 * time.Hour)},
							EndDate:     &date.Time{now.Add(1 * time.Hour)},
							KeyID:       &keyID,
						},
					},
				},
			}

			expiration := now.Add(6 * time.Hour)

			mockProvider := NewMockAzureProvider(ctrl)
			mockProvider.EXPECT().ListApplications(gomock.Any(), fmt.Sprintf("appId eq '%s'", testClientID)).
				Return(apps, nil)

			newPasswordResult := api.PasswordCredentialResult{
				PasswordCredential: api.PasswordCredential{
					DisplayName: strPtr("vault-plugin-secrets-azure-someuuid"),
					StartDate:   &date.Time{now},
					EndDate:     &date.Time{expiration},
					KeyID:       strPtr("new-credential"),
					SecretText:  strPtr("myreallysecurepassword"),
				},
			}
			mockProvider.EXPECT().AddApplicationPassword(gomock.Any(), objID, gomock.Any(), expiration).
				Return(newPasswordResult, nil)

			mockProvider.EXPECT().RemoveApplicationPassword(gomock.Any(), objID, keyID).Return(nil)

			b.getProvider = func(_ *clientSettings, _ bool, _ api.Passwords) (api.AzureProvider, error) {
				return mockProvider, nil
			}

			client, err := b.getClient(ctx, storage)
			assertErrorIsNil(t, err)
			assertNotNil(t, client)

			passCred, warnings, err := b.rotateRootCredentials(ctx, storage, *originalCfg, expiration)
			assertErrorIsNil(t, err)
			assertStrSliceIsEmpty(t, warnings)

			expectedCred := newPasswordResult.PasswordCredential

			if !reflect.DeepEqual(passCred, expectedCred) {
				t.Fatalf("Expected: %#v\nActual: %#v", expectedCred, passCred)
			}

			updatedCfg, err := b.getConfig(ctx, storage)
			assertErrorIsNil(t, err)

			if reflect.DeepEqual(updatedCfg, originalCfg) {
				t.Fatalf("New config should not equal the original config")
			}

			if updatedCfg.ClientSecret != *newPasswordResult.PasswordCredential.SecretText {
				t.Fatalf("Expected client secret: %s Actual client secret: %s", *newPasswordResult.PasswordCredential.SecretText, updatedCfg.ClientSecret)
			}

			wals, err := framework.ListWAL(ctx, storage)
			assertErrorIsNil(t, err)

			assertStrSliceIsEmpty(t, wals)
		})
	}
}

func TestIntersectStrings(t *testing.T) {
	type testCase struct {
		a      []string
		b      []string
		expect []string
	}

	tests := map[string]testCase{
		"nil slices": {
			a:      nil,
			b:      nil,
			expect: []string{},
		},
		"a is nil": {
			a:      nil,
			b:      []string{"foo"},
			expect: []string{},
		},
		"b is nil": {
			a:      []string{"foo"},
			b:      nil,
			expect: []string{},
		},
		"a is empty": {
			a:      []string{},
			b:      []string{"foo"},
			expect: []string{},
		},
		"b is empty": {
			a:      []string{"foo"},
			b:      []string{},
			expect: []string{},
		},
		"a equals b": {
			a:      []string{"foo"},
			b:      []string{"foo"},
			expect: []string{"foo"},
		},
		"a equals b (many)": {
			a:      []string{"foo", "bar", "baz", "qux", "quux", "quuz"},
			b:      []string{"foo", "bar", "baz", "qux", "quux", "quuz"},
			expect: []string{"foo", "bar", "baz", "qux", "quux", "quuz"},
		},
		"a equals b but out of order": {
			a:      []string{"foo", "bar", "baz", "qux", "quux", "quuz"},
			b:      []string{"quuz", "bar", "qux", "foo", "quux", "baz"},
			expect: []string{"quuz", "bar", "qux", "foo", "quux", "baz"},
		},
		"a is superset": {
			a:      []string{"foo", "bar", "baz"},
			b:      []string{"foo"},
			expect: []string{"foo"},
		},
		"a is superset out of order": {
			a:      []string{"bar", "foo", "baz"},
			b:      []string{"foo"},
			expect: []string{"foo"},
		},
		"b is superset": {
			a:      []string{"foo"},
			b:      []string{"foo", "bar", "baz"},
			expect: []string{"foo"},
		},
		"b is superset out of order": {
			a:      []string{"foo"},
			b:      []string{"bar", "foo", "baz"},
			expect: []string{"foo"},
		},
		"a not equal to b": {
			a:      []string{"foo", "bar", "baz"},
			b:      []string{"qux", "quux", "quuz"},
			expect: []string{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := intersectStrings(test.a, test.b)
			if !reflect.DeepEqual(actual, test.expect) {
				t.Fatalf("Actual: %#v\nExpected: %#v\n", actual, test.expect)
			}
		})
	}
}

func assertNotNil(t *testing.T, val interface{}) {
	t.Helper()
	if val == nil {
		t.Fatalf("expected not nil, but was nil")
	}
}

func assertStrSliceIsEmpty(t *testing.T, strs []string) {
	t.Helper()
	if strs != nil && len(strs) > 0 {
		t.Fatalf("string slice is not empty")
	}
}

func strPtr(str string) *string {
	return &str
}
