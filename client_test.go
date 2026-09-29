// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	t.Parallel()
	t.Run("First try success", func(t *testing.T) {
		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			return nil, true, nil
		})
		assertErrorIsNil(t, err)
	})

	t.Run("Three retries", func(t *testing.T) {
		t.Parallel()
		count := 0

		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			count++
			if count >= 3 {
				return nil, true, nil
			}
			return nil, false, nil
		})
		equal(t, count, 3)

		assertErrorIsNil(t, err)
	})

	t.Run("Error on attempt", func(t *testing.T) {
		t.Parallel()
		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			return nil, true, errors.New("Fail")
		})
		if err == nil || !strings.Contains(err.Error(), "Fail") {
			t.Fatalf("expected failure error, got: %v", err)
		}
	})

	// timeout test
	t.Run("Timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode.")
		}
		t.Parallel()
		start := time.Now()

		timeout := 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		called := 0
		_, err := retry(ctx, func() (interface{}, bool, error) {
			called++
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if called == 0 {
			t.Fatalf("retryable function was never called")
		}
		assertDuration(t, elapsed, timeout, 250*time.Millisecond)
	})

	t.Run("Cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(1 * time.Second)
			cancel()
		}()

		start := time.Now()
		_, err := retry(ctx, func() (interface{}, bool, error) {
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		assertDuration(t, elapsed, 1*time.Second, 250*time.Millisecond)

		if err == nil {
			t.Fatalf("expected err: got nil")
		}
		underlyingErr := errors.Unwrap(err)
		if underlyingErr != context.Canceled {
			t.Fatalf("expected %s, got: %v", context.Canceled, err)
		}
	})
}

// TestSPCreate_RetryLogic ensures createSP invokes retry logic when provider.CreateServicePrincipal
// repeatedly returns transient Azure-style errors before eventually succeeding.
func TestSPCreate_RetryLogic(t *testing.T) {
	t.Parallel()

	// Use the mock backend so we can inject our modified mockProvider
	b, s := getTestBackendMocked(t, true)

	// Create a mock provider with deterministic SP failures
	mp := newMockProvider().(*mockProvider)
	mp.failNextCreateServicePrincipal = true // enable the failure mode
	mp.servicePrincipalFailureCount = 3      // fail first 3 calls
	mp.servicePrincipalCalls = 0             // track total calls

	// Patch the backend to return our custom mock provider
	b.getProvider = func(ctx context.Context, lg hclog.Logger, sys logical.SystemView, cs *clientSettings) (AzureProvider, error) {
		return mp, nil
	}

	// Create a fake role so the backend will try to issue creds
	roleName := generateUUID()
	testRoleCreate(t, b, s, roleName, testRole)

	// Requesting credentials triggers: CreateApplication -> CreateServicePrincipal
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + roleName,
		Storage:   s,
	})

	// The retry logic should hide the transient failures
	if err != nil {
		t.Fatalf("Expected retry logic to recover but got error: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("Unexpected Vault response error: %#v", resp.Error())
	}

	// Validate retry behavior: 3 failures + 1 success = 4 calls
	if mp.servicePrincipalCalls != 4 {
		t.Fatalf("Expected 4 calls (3 failures + 1 success), got %d", mp.servicePrincipalCalls)
	}
}

// assertDuration with a certain amount of flex in the exact value
func assertDuration(t *testing.T, actual, expected, delta time.Duration) {
	t.Helper()

	diff := actual - expected
	if diff < 0 {
		diff = -diff
	}

	if diff > delta {
		t.Fatalf("Actual duration %s does not equal expected %s with delta %s", actual, expected, delta)
	}
}

func TestIsSPCreatePropagationError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                    {err: nil, want: false},
		"local tenant":           {err: errors.New("the backing application of the service principal being created must be in the local tenant"), want: true},
		"invalid app object":     {err: errors.New("appId does not reference a valid application object"), want: true},
		"authorization denied":   {err: errors.New("Authorization_RequestDenied"), want: true},
		"propagation":            {err: errors.New("waiting for propagation"), want: true},
		"please try again":       {err: errors.New("Please try again later"), want: true},
		"could not find":         {err: errors.New("could not find application"), want: true},
		"not found":              {err: errors.New("Request_ResourceNotFound: resource not found"), want: true},
		"reference-property":     {err: errors.New("Resource 'ff3670fa-434f-46cb-8ca8-f93e5b8f0493' does not exist or one of its queried reference-property objects are not present."), want: true},
		"permission not granted": {err: errors.New("Insufficient privileges to complete the operation."), want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := isSPCreatePropagationError(tc.err); got != tc.want {
				t.Fatalf("isSPCreatePropagationError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestSPCreate_RetryLogic_ReferencePropertyNotPresent ensures createSP retries the
// "does not exist or one of its queried reference-property objects are not present"
// error Microsoft Graph returns while a new application is still replicating.
func TestSPCreate_RetryLogic_ReferencePropertyNotPresent(t *testing.T) {
	t.Parallel()

	b, s := getTestBackendMocked(t, true)

	mp := newMockProvider().(*mockProvider)
	mp.failNextCreateServicePrincipal = true
	mp.servicePrincipalFailureCount = 2
	mp.servicePrincipalFailureMessage = "Resource 'ff3670fa-434f-46cb-8ca8-f93e5b8f0493' does not exist or one of its queried reference-property objects are not present."

	b.getProvider = func(ctx context.Context, lg hclog.Logger, sys logical.SystemView, cs *clientSettings) (AzureProvider, error) {
		return mp, nil
	}

	roleName := generateUUID()
	testRoleCreate(t, b, s, roleName, testRole)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + roleName,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("Expected retry logic to recover but got error: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("Unexpected Vault response error: %#v", resp.Error())
	}
	if mp.servicePrincipalCalls != 3 {
		t.Fatalf("Expected 3 calls (2 failures + 1 success), got %d", mp.servicePrincipalCalls)
	}
}
