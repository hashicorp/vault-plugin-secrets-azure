package azuresecrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

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
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8200/v1/local-azure/creds/test-role", nil)
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
	fmt.Println("client_id: ", clientID)
	fmt.Println("clientSecret: ", clientSecret)

	// Introduce a delay between generating creds and using them
	// time.Sleep(5 * time.Second)

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
			count, err := helper(ctx, resourceGroupClient)
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

	err = cleanup(ctx, resourceGroupClient)
	assert.NoError(t, err)
}

func helper(ctx context.Context, rgClient *armresources.ResourceGroupsClient) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
	resp, err := rgClient.CreateOrUpdate(ctx, fmt.Sprintf("%v-%v", "vault-test", uuid.New().String()), armresources.ResourceGroup{
		Location: to.StringPtr("West US"),
		Tags:     map[string]*string{"created_by": to.StringPtr("vault-test-{UUID}")},
	}, nil)
	if err != nil {
		return armresources.ResourceGroupsClientCreateOrUpdateResponse{}, err
	}
	return resp, nil
}

func cleanup(ctx context.Context, rgClient *armresources.ResourceGroupsClient) error {
	pager := rgClient.NewListPager(&armresources.ResourceGroupsClientListOptions{
		Filter: to.StringPtr("tagName eq 'created_by' and tagValue eq 'vault-test-{UUID}'"),
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
