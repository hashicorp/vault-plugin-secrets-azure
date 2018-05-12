package azuresecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/logical"
	"github.com/stretchr/testify/assert"
)

func TestCredentialRead(t *testing.T) {
	assert := assert.New(t)
	b, s := getTestBackend(t)
	data := map[string]interface{}{
		"roles": `
	[
		{
			"role_id": "/subscriptions/35c0f55a-1c70-45d4-a11f-7cdb3d4f6c24/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
			"scope":  "/subscriptions/35c0f55a-1c70-45d4-a11f-7cdb3d4f6c24"
		},
		{
			"role_id": "/subscriptions/35c0f55a-1c70-45d4-a11f-7cdb3d4f6c24/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"scope":  "/subscriptions/35c0f55a-1c70-45d4-a11f-7cdb3d4f6c24"
		}
	]`,
	}

	//d := parseJSON(t, data)

	//	fmt.Println(d)
	err := testRolesCreate(t, b, s, "test_role", data)
	assert.Nil(err)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "credential/test_role",
		Storage:   s,
	})

	assert.Nil(err)
	assert.NotNil(resp)
	assert.False(resp.IsError())
}

func testRolesCreate(t *testing.T, b *azureSecretBackend, s logical.Storage, name string, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roles/credential/%s", name),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

/*
func testConfigCreate(t *testing.T, b *azureSecretBackend, s logical.Storage, d interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("config"),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
*/

func parseJSON(t *testing.T, s string) map[string]interface{} {
	var a map[string]interface{}

	err := json.Unmarshal([]byte(s), &a)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
