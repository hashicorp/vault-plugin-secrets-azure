package azuresecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// confirms that credentials are properly provisioned on static role creation
func TestStaticCred_Read(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	// 30 days in seconds
	credTTL := 60 * 60 * 24 * 30

	// create a static role, which in turn creates the Azure credential
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      pathStaticRole + roleName,
		Data: map[string]interface{}{
			paramApplicationObjectID: appObjID,
			paramTTL:                 credTTL,
		},
		Storage: s,
	})
	assertRespNoError(t, resp, err)

	// read the Azure credential to ensure that it was properly created
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      pathStaticCreds + roleName,
		Storage:   s,
	})
	assertRespNoError(t, resp, err)

	// ensure that the credential's info can be retreived successfully
	assertNotEmptyString(t, resp.Data["client_id"].(string))
	assertNotEmptyString(t, resp.Data["secret_id"].(string))
	assertNotEmptyString(t, resp.Data["client_secret"].(string))
	assertNotEmptyString(t, resp.Data["expiration"].(string))

	// verify that the expiration matches the TTL
	expirationStr := resp.Data["expiration"].(string)
	expiration, err := time.Parse(time.RFC3339, expirationStr)
	assert.NoError(t, err)

	// Calculate the expected expiration time (current time + TTL)
	expectedExpiration := time.Now().Add(time.Duration(credTTL) * time.Second)

	// Allow for a small time difference (within 5 seconds) due to processing time
	assert.WithinDuration(t, expectedExpiration, expiration, 5*time.Second,
		"expiration should be within 5 seconds of expected TTL-based expiration")
}

// confirms that the secret id and client secret change upon rotation
// and that a rotation attempt on a nonexistent role fails
func TestStaticCred_Rotate(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	// create a static role, which in turn creates the Azure credential
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      pathStaticRole + roleName,
		Data: map[string]interface{}{
			paramApplicationObjectID: appObjID,
		},
		Storage: s,
	})
	assertRespNoError(t, resp, err)

	// read the Azure credential to ensure that it was properly created
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      pathStaticCreds + roleName,
		Storage:   s,
	})
	assertRespNoError(t, resp, err)

	originalSecretId := resp.Data["secret_id"].(string)
	originalClientSecret := resp.Data["client_secret"].(string)

	// ensure that the secret id and client secret were provisioned on role creation
	assertNotEmptyString(t, originalSecretId)
	assertNotEmptyString(t, originalClientSecret)

	// Test rotation scenarios
	cases := []struct {
		name           string
		path           string
		operation      logical.Operation
		expectError    bool
		expectRotation bool
	}{
		{
			name:           "rotate nonexistent role",
			path:           pathRotateRole + "nonexistent-role",
			operation:      logical.UpdateOperation,
			expectError:    true,
			expectRotation: false,
		},
		{
			name:           "rotate existing role",
			path:           pathRotateRole + roleName,
			operation:      logical.UpdateOperation,
			expectError:    false,
			expectRotation: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: tc.operation,
				Path:      tc.path,
				Storage:   s,
			})

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assertRespNoError(t, resp, err)

			if tc.expectRotation {
				// Verify the credentials have changed
				resp, err = b.HandleRequest(context.Background(), &logical.Request{
					Operation: logical.ReadOperation,
					Path:      pathStaticCreds + roleName,
					Storage:   s,
				})
				assertRespNoError(t, resp, err)

				newSecretId := resp.Data["secret_id"].(string)
				newClientSecret := resp.Data["client_secret"].(string)

				assertNotEmptyString(t, newSecretId)
				assertNotEmptyString(t, newClientSecret)

				// ensure that the original secret id and client secret are different from the new ones
				assert.NotEqual(t, originalSecretId, newSecretId)
				assert.NotEqual(t, originalClientSecret, newClientSecret)
			}
		})
	}
}
