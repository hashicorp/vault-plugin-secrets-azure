package azuresecrets

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type azureSecretBackend struct {
	*framework.Backend

	provider     Provider
	providerLock sync.RWMutex
	cfgLock      sync.RWMutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *azureSecretBackend {
	var b = azureSecretBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: framework.PathAppend(
			pathsRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathServicePrincipal(&b),
			},
		),
		Secrets: []*framework.Secret{
			secretServicePrincipal(&b),
		},

		BackendType:       logical.TypeLogical,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,
	}

	return &b
}

func (b *azureSecretBackend) getProvider(settings *azureSettings) (p Provider, err error) {
	b.providerLock.Lock()
	defer b.providerLock.Unlock()

	if b.provider != nil {
		return b.provider, nil
	}

	if b.provider, err = NewAzureProvider(settings); err != nil {
		return nil, err
	}

	return b.provider, nil
}

func (b *azureSecretBackend) reset() {
	b.providerLock.Lock()
	defer b.providerLock.Unlock()

	b.provider = nil
}

const backendHelp = `
The Azure secrets backend dynamically generates Azure service
principals and/or User Assigned Identity assignments. Both types
of credentials have a configurable lease set and are automatically
revoked at the end of the lease.

After mounting this backend, credentials to manage Azure resources
must be configured with the "config/" endpoints and policies must be
written using the "roles/" endpoints before any credentials can be
generated.
`
