package azuresecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
)

const (
	walTypeCredential = "credential"
)

type walCredential struct {
	AppObjectID string
}

func (b *azureSecretBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walTypeCredential:
		return b.spRollback(ctx, req, data)
	default:
		return fmt.Errorf("unknown type to rollback")
	}
}
