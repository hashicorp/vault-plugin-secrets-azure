package api

import (
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

type TokenClient interface {
	GetToken(c auth.ClientCredentialsConfig) (adal.Token, error)
}

var _ TokenClient = (*AccessTokenClient)(nil)

type AccessTokenClient struct{}

// GetToken fetches a new Azure OAuth2 bearer token from the given clients
// credentials and tenant.
func (p *AccessTokenClient) GetToken(c auth.ClientCredentialsConfig) (adal.Token, error) {
	t, err := c.ServicePrincipalToken()
	if err != nil {
		return adal.Token{}, err
	}

	err = t.Refresh()
	if err != nil {
		return adal.Token{}, err
	}

	return t.Token(), nil
}
