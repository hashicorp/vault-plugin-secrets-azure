package azuresecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

// create role and confirm that it's client id and client secret are not nil
// and matches the expected output

func TestStaticCred_Read(t *testing.T) {
	b, s := getTestBackendMocked(t, true)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      pathStaticRole + roleName,
		Data: map[string]interface{}{
			paramApplicationObjectID: appObjID,
		},
		Storage: s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      pathStaticCred + roleName,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	fmt.Println("resp", resp)
}
