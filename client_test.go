// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
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

		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("Error preservation on timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode.")
		}
		t.Parallel()

		timeout := 5 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		expectedErr := errors.New("Resource does not exist or one of its queried reference-property objects are not present")
		_, err := retry(ctx, func() (interface{}, bool, error) {
			// Simulate retryable error that never succeeds
			return nil, false, expectedErr
		})

		if err == nil {
			t.Fatalf("expected error, got nil")
		}

		// Verify the original error is preserved in the retry failure message
		if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("expected error to contain original message %q, got: %v", expectedErr.Error(), err)
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

	// Requesting credentials triggers: CreateApplicationWithPassword -> CreateServicePrincipalWithoutPassword
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

// TestSPCreate_AzurePropagationErrors verifies that the retry logic correctly identifies
// and retries on Azure propagation delay error messages, including the "does not exist"
// and "reference-property" patterns reported in customer support tickets.
func TestSPCreate_AzurePropagationErrors(t *testing.T) {
	t.Parallel()

	// Test cases covering various Azure propagation error messages
	testCases := []struct {
		name         string
		errorMessage string
		shouldRetry  bool
	}{
		{
			name:         "reference-property error",
			errorMessage: "Resource '0c760b20-e7a6-4611-950c-68ff06816696' does not exist or one of its queried reference-property objects are not present",
			shouldRetry:  true,
		},
		{
			name:         "does not exist error",
			errorMessage: "Application with identifier 'abc123' does not exist in the directory",
			shouldRetry:  true,
		},
		{
			name:         "local tenant error",
			errorMessage: "When using this permission, the backing application of the service principal being created must be in the local tenant",
			shouldRetry:  true,
		},
		{
			name:         "not found error",
			errorMessage: "Application not found",
			shouldRetry:  true,
		},
		{
			name:         "propagation error",
			errorMessage: "Changes are still propagating, please try again",
			shouldRetry:  true,
		},
		{
			name:         "non-retryable error",
			errorMessage: "Insufficient privileges to complete the operation",
			shouldRetry:  false,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, s := getTestBackendMocked(t, true)
			mp := newMockProvider().(*mockProvider)

			// Configure mock to fail with specific error message
			mp.servicePrincipalErrorMessage = tc.errorMessage
			if tc.shouldRetry {
				mp.servicePrincipalFailureCount = 2 // Fail twice, then succeed
			} else {
				mp.servicePrincipalFailureCount = 100 // Always fail for non-retryable
			}
			mp.servicePrincipalCalls = 0

			b.getProvider = func(ctx context.Context, lg hclog.Logger, sys logical.SystemView, cs *clientSettings) (AzureProvider, error) {
				return mp, nil
			}

			roleName := generateUUID()
			testRoleCreate(t, b, s, roleName, testRole)

			// Set a shorter timeout for non-retryable errors
			ctx := context.Background()
			if !tc.shouldRetry {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
			}

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/" + roleName,
				Storage:   s,
			})

			if tc.shouldRetry {
				// Should succeed after retries
				if err != nil {
					t.Fatalf("Expected retry logic to recover from %q, but got error: %v", tc.errorMessage, err)
				}
				if resp.IsError() {
					t.Fatalf("Expected success after retries, got response error: %v", resp.Error())
				}
				// Verify it actually retried
				if mp.servicePrincipalCalls <= 1 {
					t.Fatalf("Expected multiple calls due to retries, got %d", mp.servicePrincipalCalls)
				}
			} else {
				// Should fail without retrying extensively
				if err == nil && !resp.IsError() {
					t.Fatalf("Expected non-retryable error %q to fail", tc.errorMessage)
				}
				// Verify the original error message is preserved
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				} else if resp.IsError() {
					errMsg = resp.Error().Error()
				}
				if !strings.Contains(errMsg, tc.errorMessage) {
					t.Fatalf("Expected error to contain %q, got: %v", tc.errorMessage, errMsg)
				}
			}
		})
	}
}

// TestRoleAssignment_RetryLogic verifies that role assignment retries on PrincipalNotFound
// errors and preserves error messages when retries are exhausted.
func TestRoleAssignment_RetryLogic(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		failureCount  int
		errorMessage  string
		shouldSucceed bool
		expectRetries bool
	}{
		{
			name:          "success after retries on PrincipalNotFound",
			failureCount:  2,
			errorMessage:  "PrincipalNotFound",
			shouldSucceed: true,
			expectRetries: true,
		},
		{
			name:          "error message preserved on timeout",
			failureCount:  100, // Will exhaust retries
			errorMessage:  "PrincipalNotFound - service principal not replicated",
			shouldSucceed: false,
			expectRetries: true,
		},
		{
			name:          "non-retryable error fails immediately",
			failureCount:  100,
			errorMessage:  "Insufficient privileges",
			shouldSucceed: false,
			expectRetries: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, s := getTestBackendMocked(t, true)
			mp := newMockProvider().(*mockProvider)

			// Configure role assignment failures
			mp.roleAssignmentErrorMessage = tc.errorMessage
			mp.roleAssignmentFailureCount = tc.failureCount
			mp.roleAssignmentCalls = 0

			b.getProvider = func(ctx context.Context, lg hclog.Logger, sys logical.SystemView, cs *clientSettings) (AzureProvider, error) {
				return mp, nil
			}

			// Create a role with Azure role assignments
			roleName := generateUUID()
			roleData := map[string]interface{}{
				"azure_roles": encodeJSON([]AzureRole{
					{
						RoleName: "Contributor",
						RoleID:   "/subscriptions/FAKE_SUB_ID/providers/Microsoft.Authorization/roleDefinitions/FAKE_ROLE-Contributor",
						Scope:    "/subscriptions/test-subscription",
					},
				}),
			}
			testRoleCreate(t, b, s, roleName, roleData)

			// Set timeout for non-retryable errors
			ctx := context.Background()
			if !tc.expectRetries {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
			}

			// Request credentials - this triggers role assignment
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/" + roleName,
				Storage:   s,
			})

			if tc.shouldSucceed {
				if err != nil {
					t.Fatalf("Expected success after retries, got error: %v", err)
				}
				if resp.IsError() {
					t.Fatalf("Expected success, got response error: %v", resp.Error())
				}
				// Verify retries occurred
				if mp.roleAssignmentCalls <= 1 {
					t.Fatalf("Expected multiple role assignment calls due to retries, got %d", mp.roleAssignmentCalls)
				}
			} else {
				// Should fail
				if err == nil && !resp.IsError() {
					t.Fatalf("Expected failure for error %q", tc.errorMessage)
				}

				// Verify error message is preserved
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				} else if resp.IsError() {
					errMsg = resp.Error().Error()
				}

				if !strings.Contains(errMsg, tc.errorMessage) {
					t.Fatalf("Expected error to contain %q, got: %v", tc.errorMessage, errMsg)
				}

				// Verify retry behavior
				if tc.expectRetries && mp.roleAssignmentCalls <= 1 {
					t.Fatalf("Expected multiple retry attempts, got %d calls", mp.roleAssignmentCalls)
				} else if !tc.expectRetries && mp.roleAssignmentCalls > 2 {
					t.Fatalf("Expected minimal retries for non-retryable error, got %d calls", mp.roleAssignmentCalls)
				}
			}
		})
	}
}

// TestIsObjectNotYetVisibleError verifies which Microsoft Graph errors are treated as
// the referenced object not having propagated yet.
func TestIsObjectNotYetVisibleError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "graph error message for a just-created object",
			err:  errors.New("Resource '0c760b20-e7a6-4611-950c-68ff06816696' does not exist or one of its queried reference-property objects are not present."),
			want: true,
		},
		{
			name: "graph error code",
			err:  errors.New("Request_ResourceNotFound"),
			want: true,
		},
		{
			name: "wrapped error",
			err:  fmt.Errorf("wrapped: %w", errors.New("Resource 'abc' does not exist or one of its queried reference-property objects are not present.")),
			want: true,
		},
		{
			name: "non-retryable error",
			err:  errors.New("Insufficient privileges to complete the operation."),
			want: false,
		},
		{
			name: "graph ODataError with Request_ResourceNotFound code",
			err:  newODataError("Request_ResourceNotFound", "Not Found"),
			want: true,
		},
		{
			name: "graph ODataError with the not-found message",
			err:  newODataError("", "Resource 'abc' does not exist or one of its queried reference-property objects are not present."),
			want: true,
		},
		{
			name: "wrapped graph ODataError with Request_ResourceNotFound code",
			err:  fmt.Errorf("wrapped: %w", newODataError("Request_ResourceNotFound", "Not Found")),
			want: true,
		},
		{
			name: "graph ODataError with another code",
			err:  newODataError("Authorization_RequestDenied", "Insufficient privileges to complete the operation."),
			want: false,
		},
		{
			name: "graph ODataError without code or message",
			err:  odataerrors.NewODataError(),
			want: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isObjectNotYetVisibleError(tc.err))
		})
	}
}

// newODataError builds a Microsoft Graph SDK error with the given code and message.
// Empty values are left unset.
func newODataError(code, message string) *odataerrors.ODataError {
	mainErr := odataerrors.NewMainError()
	if code != "" {
		mainErr.SetCode(&code)
	}
	if message != "" {
		mainErr.SetMessage(&message)
	}

	odataErr := odataerrors.NewODataError()
	odataErr.SetErrorEscaped(mainErr)
	return odataErr
}

// TestGroupMembership_RetryLogic verifies that adding the new service principal to its
// groups retries when Microsoft Graph doesn't see the service principal yet, and fails
// fast with the original error otherwise.
func TestGroupMembership_RetryLogic(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		failureCount  int
		graphErrCode  string // when set, the mock returns a Graph SDK ODataError with this code
		errorMessage  string
		shouldSucceed bool
		expectRetries bool
	}{
		{
			name:          "success after retries on does not exist message",
			failureCount:  2,
			errorMessage:  "Resource '0c760b20-e7a6-4611-950c-68ff06816696' does not exist or one of its queried reference-property objects are not present.",
			shouldSucceed: true,
			expectRetries: true,
		},
		{
			name:          "success after retries on Request_ResourceNotFound",
			failureCount:  2,
			errorMessage:  "Request_ResourceNotFound",
			shouldSucceed: true,
			expectRetries: true,
		},
		{
			name:          "success after retries on graph ODataError code",
			failureCount:  2,
			graphErrCode:  "Request_ResourceNotFound",
			errorMessage:  "Not Found",
			shouldSucceed: true,
			expectRetries: true,
		},
		{
			name:          "non-retryable error fails immediately",
			failureCount:  100,
			errorMessage:  "Insufficient privileges to complete the operation.",
			shouldSucceed: false,
			expectRetries: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, s := getTestBackendMocked(t, true)
			mp := newMockProvider().(*mockProvider)

			if tc.graphErrCode != "" {
				mp.groupMemberError = newODataError(tc.graphErrCode, tc.errorMessage)
			}
			mp.groupMemberErrorMessage = tc.errorMessage
			mp.groupMemberFailureCount = tc.failureCount
			mp.groupMemberCalls = 0

			b.getProvider = func(ctx context.Context, lg hclog.Logger, sys logical.SystemView, cs *clientSettings) (AzureProvider, error) {
				return mp, nil
			}

			// Create a role with a group membership
			roleName := generateUUID()
			roleData := map[string]interface{}{
				"azure_groups": compactJSON(`[{"group_name": "foo", "object_id": "239b11fe-6adf-409a-b231-08b918e9de23FAKE_GROUP-foo"}]`),
			}
			testRoleCreate(t, b, s, roleName, roleData)

			ctx := context.Background()
			if !tc.expectRetries {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
			}

			// Request credentials - this triggers adding the group membership
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/" + roleName,
				Storage:   s,
			})

			if tc.shouldSucceed {
				if err != nil {
					t.Fatalf("Expected success after retries, got error: %v", err)
				}
				if resp.IsError() {
					t.Fatalf("Expected success, got response error: %v", resp.Error())
				}
				if mp.groupMemberCalls <= 1 {
					t.Fatalf("Expected multiple group membership calls due to retries, got %d", mp.groupMemberCalls)
				}
				return
			}

			if err == nil && !resp.IsError() {
				t.Fatalf("Expected failure for error %q", tc.errorMessage)
			}

			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			} else if resp.IsError() {
				errMsg = resp.Error().Error()
			}
			if !strings.Contains(errMsg, tc.errorMessage) {
				t.Fatalf("Expected error to contain %q, got: %v", tc.errorMessage, errMsg)
			}
			if !tc.expectRetries && mp.groupMemberCalls > 1 {
				t.Fatalf("Expected no retries for non-retryable error, got %d calls", mp.groupMemberCalls)
			}
		})
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
