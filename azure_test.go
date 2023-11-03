package azuresecrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

// Steps to reproduce the error for Azure eventual consistency issue:
//
//  1. Enable the Azure secrets engine
//     $ vault secrets enable azure
//
//  2. Configure the secrets engine with account creds (these creds can be found by
//     logging in to Azure portal (1password) and searching for Team Vault subscription.
//     $ vault write azure/config \
//     subscription_id=$AZURE_SUBSCRIPTION_ID \
//     tenant_id=$AZURE_TENANT_ID \
//     client_id=$AZURE_CLIENT_ID \
//     client_secret=$AZURE_CLIENT_SECRET
//
//  3. To run this test with an app id, you need to register an application in the Azure portal.
//     App registrations → New registration → Register
//     You will need to add following API permissions to your application:
//     - Application.ReadWrite.All
//     - GroupMember.ReadWrite.All
//     Make sure to Grant admin consent for Default Directory.
//     Go to Team Vault Subscription → Access control (IAM) → Add role assignment → Privileged administrator roles →
//     Select Owner → Go to Members → Select Members → Add the application you just registered →
//     Not constrained Delegation type → Review and assign
//
//     Create a role with an already existing application id
//     $ vault write azure/roles/test-role \
//     application_object_id=<existing_app_obj_id> \
//     ttl=10h
//
//  4. To configure a role to create a new sp with Azure roles:
//     $ vault write azure/roles/test-role ttl=10h azure_roles=-<<EOF
//     [
//     {
//     "role_name": "Contributor",
//     "scope":  "/subscriptions/<uuid>"
//     }
//     ]
//     EOF
type VaultCredResponse struct {
	Data struct {
		ClientId     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"data"`
}

func TestSPCredentials(t *testing.T) {
	ctx := context.Background()

	subscriptionID := os.Getenv("SUBSCRIPTION_ID")
	tenantID := os.Getenv("TENANT_ID")
	if subscriptionID == "" || tenantID == "" {
		t.SkipNow()
	}

	// use dynamic credentials from Vault instead of hardcoding them.
	// Use a regular HTTP client to make the request
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8200/v1/azure/creds/test-role", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Vault-Token", "root")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response VaultCredResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	clientID := response.Data.ClientId
	clientSecret := response.Data.ClientSecret

	// Introduce a delay between generating creds and using them
	// time.Sleep(5 * time.Second)

	newUUID := uuid.New().String()
	var successes uint64
	var wg sync.WaitGroup
	creds, err := azidentity.NewClientSecretCredential(
		tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{})
	assert.NoError(t, err)

	resourceGroupClient, err := armresources.NewResourceGroupsClient(subscriptionID, creds, nil)
	assert.NoError(t, err)
	n := 100
	var authFailures uint64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			count, err := createResourceGroup(ctx, resourceGroupClient, newUUID)
			if err == nil {
				atomic.AddUint64(&successes, 1)
				_ = count
			} else {
				if strings.Contains(err.Error(), "unauthorized_client") {
					atomic.AddUint64(&authFailures, 1)
				} else {
					fmt.Println(err)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Println("Num failures", n-int(successes))
	fmt.Println("Num Auth failures", authFailures)
	assert.EqualValues(t, n, successes, successes)

	err = cleanupResourceGroups(ctx, resourceGroupClient, newUUID)
	assert.NoError(t, err)
}

func createResourceGroup(ctx context.Context, rgClient *armresources.ResourceGroupsClient, newUUID string) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
	resp, err := rgClient.CreateOrUpdate(ctx, fmt.Sprintf("%v-%v", "vault-test", uuid.New().String()), armresources.ResourceGroup{
		Location: to.StringPtr("West US"),
		Tags:     map[string]*string{"created_by": to.StringPtr(fmt.Sprintf("vault-test-%s", newUUID))},
	}, nil)
	if err != nil {
		return armresources.ResourceGroupsClientCreateOrUpdateResponse{}, err
	}
	return resp, nil
}

func cleanupResourceGroups(ctx context.Context, rgClient *armresources.ResourceGroupsClient, newUUID string) error {
	pager := rgClient.NewListPager(&armresources.ResourceGroupsClientListOptions{
		Filter: to.StringPtr(fmt.Sprintf("tagName eq 'created_by' and tagValue eq 'vault-test-%s'", newUUID)),
		Top:    nil,
	})
	var counter uint64
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		group, ctx := errgroup.WithContext(ctx)
		for _, rg := range page.Value {
			rg := rg
			group.Go(func() error {
				atomic.AddUint64(&counter, 1)
				_, err := rgClient.BeginDelete(ctx, *rg.Name, nil)
				var azerr *azcore.ResponseError
				if errors.As(err, &azerr) {
					if azerr.StatusCode == http.StatusNotFound {
						return nil
					}
				}
				return err
			})
		}
		if err := group.Wait(); err != nil {
			return err
		}
	}
	fmt.Println("items marked for deletion", counter)
	return nil
}
