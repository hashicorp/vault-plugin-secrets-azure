package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

//import (
//	"context"
//	"encoding/base64"
//	"errors"
//	"fmt"
//	"net/http"
//	"net/url"
//	"time"
//
//	"github.com/hashicorp/errwrap"
//	"github.com/hashicorp/vault/logical"
//	"github.com/hashicorp/vault/logical/framework"
//	"golang.org/x/oauth2"
//	"golang.org/x/oauth2/google"
//	"google.golang.org/api/googleapi"
//	"google.golang.org/api/iam/v1"
//)
//
const (
	SecretTypeIdentity = "identity"

//	SecretTypeAccessToken     = "access_token"
//	revokeAccessTokenEndpoint = "https://accounts.google.com/o/oauth2/revoke"
//	revokeTokenWarning        = `revocation request was successful; however, due to how OAuth access propagation works, the OAuth token might still be valid until it expires`
)

//

func secretIdentity(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeIdentity,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "OAuth2 token",
			},
		},
		//Renew:  b.secretAccessTokenRenew,
		Revoke: b.secretAccessTokenRevoke,
	}
}

//
func pathSecretIdentity(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("identity/%s", framework.GenericNameRegex("roleset")),
		Fields: map[string]*framework.FieldSchema{
			"roleset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
		},
		//ExistenceCheck: b.pathRoleSetExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathIdentity,
			logical.UpdateOperation: b.pathIdentity,
		},
		//HelpSynopsis:    pathTokenHelpSyn,
		//HelpDescription: pathTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathIdentity(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rsName := d.Get("roleset").(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	//if rs == nil {
	//	return logical.ErrorResponse(fmt.Sprintf("role set '%s' does not exists", rsName)), nil
	//}

	//if rs.SecretType != SecretTypeAccessToken {
	//	return logical.ErrorResponse(fmt.Sprintf("role set '%s' cannot generate access tokens (has secret type %s)", rsName, rs.SecretType)), nil
	//}

	return b.getSecretIdentity(ctx, req.Storage, rs)
}

//
//func (b *backend) secretAccessTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
//	// Renewal not allowed
//	return logical.ErrorResponse("short-term access tokens cannot be renewed - request new access token instead"), nil
//}

func (b *azureSecretBackend) secretAccessTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := b.removeMachineIdentities(ctx, "msi_test_central", "identity-test-vm5", []string{
		"/subscriptions/xxxxxxxxxxxxxxxxxxxxx/resourcegroups/msi_test_central/providers/Microsoft.ManagedIdentity/userAssignedIdentities/b",
	})
	//tokenRaw, ok := req.Secret.InternalData["access_token"]
	//if !ok {
	//	return nil, fmt.Errorf("secret is missing token internal data")
	//}

	//resp, err := http.Get(revokeAccessTokenEndpoint + fmt.Sprintf("?token=%s", url.QueryEscape(tokenRaw.(string))))
	//if err != nil {
	//	return logical.ErrorResponse(fmt.Sprintf("revoke returned error: %v", err)), nil
	//}
	//if err := googleapi.CheckResponse(resp); err != nil {
	//	return logical.ErrorResponse(err.Error()), nil
	//}

	//return &logical.Response{
	//	Warnings: []string{revokeTokenWarning},
	//}, nil
	return nil, err
}

func (b *azureSecretBackend) getSecretIdentity(ctx context.Context, s logical.Storage, rs *IdentityRole) (*logical.Response, error) {
	//iamC, err := newIamAdmin(ctx, s)
	//if err != nil {
	//	return nil, errwrap.Wrapf("could not create IAM Admin client: {{err}}", err)
	//}

	//// Verify account still exists
	//_, err = rs.getServiceAccount(iamC)
	//if err != nil {
	//	return logical.ErrorResponse(fmt.Sprintf("could not get role set service account: %v", err)), nil
	//}

	//if rs.TokenGen == nil || rs.TokenGen.KeyName == "" {
	//	return logical.ErrorResponse(fmt.Sprintf("invalid role set has no service account key, must be updated (path roleset/%s/rotate-key) before generating new secrets", rs.Name)), nil
	//}

	//token, err := rs.TokenGen.getAccessToken(ctx, iamC)
	//if err != nil {
	//	return logical.ErrorResponse(fmt.Sprintf("could not generate token: %v", err)), nil
	//}
	err := b.addMachineIdentities(ctx, "msi_test_central", "identity-test-vm5", []string{
		"/subscriptions/xxxxxxxxxxxxxxxxxxxxx/resourcegroups/msi_test_central/providers/Microsoft.ManagedIdentity/userAssignedIdentities/b",
	})

	secretD := map[string]interface{}{
		"token": "abc123", // token.AccessToken,
	}
	internalD := map[string]interface{}{
		"foo": "bar",
		//"access_token":      token.AccessToken,
		//"key_name":          rs.TokenGen.KeyName,
		//"role_set":          rs.Name,
		//"role_set_bindings": rs.bindingHash(),
	}
	resp := b.Secret(SecretTypeIdentity).Response(secretD, internalD)
	resp.Secret.TTL = 30 * time.Second //token.Expiry.Sub(time.Now())
	resp.Secret.Renewable = false

	return resp, err
}

//
//func (tg *TokenGenerator) getAccessToken(ctx context.Context, iamAdmin *iam.Service) (*oauth2.Token, error) {
//	key, err := iamAdmin.Projects.ServiceAccounts.Keys.Get(tg.KeyName).Do()
//	if err != nil {
//		return nil, errwrap.Wrapf("could not verify key used to generate tokens: {{err}}", err)
//	}
//	if key == nil {
//		return nil, errors.New("could not find key used to generate tokens, must update role set")
//	}
//
//	jsonBytes, err := base64.StdEncoding.DecodeString(tg.B64KeyJSON)
//	if err != nil {
//		return nil, errwrap.Wrapf("could not b64-decode key data: {{err}}", err)
//	}
//
//	cfg, err := google.JWTConfigFromJSON(jsonBytes, tg.Scopes...)
//	if err != nil {
//		return nil, errwrap.Wrapf("could not generate token JWT config: {{err}}", err)
//	}
//
//	tkn, err := cfg.TokenSource(ctx).Token()
//	if err != nil {
//		return nil, errwrap.Wrapf("could not generate token: {{err}}", err)
//	}
//	return tkn, err
//}
