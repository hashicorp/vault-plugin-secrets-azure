package azuresecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
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
