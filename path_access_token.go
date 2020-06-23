package azuresecrets

import (
	"context"
	"fmt"
	"strings"

	azureadal "github.com/Azure/go-autorest/autorest/adal"
	azureauth "github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	azureAppNotFoundErrCode = 700016
)

func pathAccessToken(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("token/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the Vault role",
			},
			"resource": {
				Type:        framework.TypeString,
				Description: "The specific Azure audience of a generated access token",
				Default:     "https://management.azure.com/",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathAccessTokenRead,
			},
		},
		HelpSynopsis:    pathAccessTokenHelpSyn,
		HelpDescription: pathAccessTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathAccessTokenRead(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	resource := data.Get("resource").(string)

	role, err := getRole(ctx, roleName, request.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role '%s' does not exist", roleName), nil
	}

	if role.CredentialType != credentialTypeSP {
		return logical.ErrorResponse("role '%s' cannot generate access tokens (has secret type %s)", roleName, role.CredentialType), nil
	}

	if role.Credentials == nil {
		return logical.ErrorResponse("role '%s' configured before plugin supported access tokens (update or recreate role)", roleName), nil
	}

	return b.secretAccessTokenResponse(ctx, request.Storage, role, resource)
}

func (b *azureSecretBackend) secretAccessTokenResponse(ctx context.Context, storage logical.Storage, role *roleEntry, resource string) (*logical.Response, error) {
	client, err := b.getClient(ctx, storage)
	if err != nil {
		return nil, err
	}

	cc := azureauth.NewClientCredentialsConfig(role.ApplicationID, role.Credentials.Password, client.settings.TenantID)
	cc.Resource = resource
	token, err := b.getToken(ctx, client, cc)
	if err != nil {
		return nil, err
	}

	// access_tokens are not revocable therefore do not return a framework.Secret (i.e. a lease)
	return &logical.Response{Data: structsMap(token)}, nil
}

func structsMap(s interface{}) map[string]interface{} {
	t := structs.New(s)
	t.TagName = "json"
	return t.Map()
}

func (b *azureSecretBackend) getToken(ctx context.Context, client *client, c azureauth.ClientCredentialsConfig) (azureadal.Token, error) {
	token, err := retry(ctx, func() (interface{}, bool, error) {
		t, err := client.provider.GetToken(c)

		if hasAzureErrorCode(err, azureAppNotFoundErrCode) {
			return nil, false, nil
		} else if err != nil {
			return nil, true, err
		}

		return t, true, nil
	})

	var t azureadal.Token
	if token != nil {
		t = token.(azureadal.Token)
	}

	return t, err
}

func hasAzureErrorCode(e error, code int) bool {
	tErr, ok := e.(azureadal.TokenRefreshError)

	// use a pattern match as TokenRefreshError is not easily parsable
	return ok && tErr != nil && strings.Contains(tErr.Error(), fmt.Sprint(code))
}

const pathAccessTokenHelpSyn = `
Request an access token for a given Vault role.
`

const pathAccessTokenHelpDesc = `
This path creates access token credentials. The associated role must
be created ahead of time with either an existing App/Service Principal or 
else a dynamic Service Principal will be created.
`
