package azuresecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// create role and confirm that it's client id and client secret are not nil
// and matches the expected output
func TestStaticCred_Read(t *testing.T) {
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
		Path:      pathStaticCred + roleName,
		Storage:   s,
	})
	assertRespNoError(t, resp, err)

	// ensure that the client id and secret have been retrieved
	assertNotEmptyString(t, resp.Data["client_id"].(string))
	assertNotEmptyString(t, resp.Data["client_secret"].(string))
}

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
		Path:      pathStaticCred + roleName,
		Storage:   s,
	})
	assertRespNoError(t, resp, err)

	originalClientID := resp.Data["client_id"].(string)
	originalClientSecret := resp.Data["client_secret"].(string)

	// ensure that the client id and secret have been retrieved
	assertNotEmptyString(t, originalClientID)
	assertNotEmptyString(t, originalClientSecret)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      pathStaticCred + roleName,
		Storage:   s,
	})

	assertRespNoError(t, resp, err)
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      pathStaticCred + roleName,
		Storage:   s,
	})

	newClientID := resp.Data["client_id"].(string)
	newClientSecret := resp.Data["client_secret"].(string)

	assertRespNoError(t, resp, err)
	assertNotEmptyString(t, newClientID)
	assertNotEmptyString(t, newClientSecret)

	// ensure that the original client id/secret is different from the new one
	assert.NotEqual(t, originalClientID, newClientID)
	assert.NotEqual(t, originalClientSecret, newClientSecret)
}
