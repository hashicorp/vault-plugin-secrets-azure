// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

type groupMembershipTestProvider struct {
	AzureProvider
	add func(context.Context, string, string) error
}

func (p *groupMembershipTestProvider) AddGroupMember(ctx context.Context, group, member string) error {
	return p.add(ctx, group, member)
}

func groupMembershipTestError(code string, status int) *odataerrors.ODataError {
	main := odataerrors.NewMainError()
	main.SetCode(&code)
	message := "Graph failure without a code in the message"
	main.SetMessage(&message)
	err := odataerrors.NewODataError()
	err.SetErrorEscaped(main)
	err.SetStatusCode(status)
	return err
}

// TestGroupMembershipRetryClassification verifies which Graph errors are retried
// and which ones start the authorization retry window.
func TestGroupMembershipRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		want       bool
		wantDenied bool
	}{
		{name: "success"},
		{name: "not found", err: groupMembershipTestError("Request_ResourceNotFound", http.StatusNotFound), want: true},
		{name: "denied", err: groupMembershipTestError("Authorization_RequestDenied", http.StatusForbidden), want: true, wantDenied: true},
		{name: "converted", err: &api.Error{Code: "request_resourcenotfound"}, want: true},
		{name: "wrong status", err: groupMembershipTestError("Authorization_RequestDenied", http.StatusBadRequest)},
		{name: "missing status", err: &api.Error{Code: "Authorization_RequestDenied"}},
		{name: "other forbidden", err: groupMembershipTestError("OtherError", http.StatusForbidden)},
		{name: "other not found", err: groupMembershipTestError("OtherError", http.StatusNotFound)},
		{name: "message only", err: errors.New("Request_ResourceNotFound Authorization_RequestDenied")},
		{name: "malformed", err: odataerrors.NewODataError()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retryable, authorizationDenied := classifyGroupMembershipError(tc.err)
			require.Equal(t, tc.want, retryable)
			require.Equal(t, tc.wantDenied, authorizationDenied)
		})
	}
}

// TestAddGroupMembershipsRecovery verifies that a transient Graph error on one
// group is retried before moving on to the next group.
func TestAddGroupMembershipsRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tc := range []struct {
		code   string
		status int
	}{
		{code: "Authorization_RequestDenied", status: http.StatusForbidden},
		{code: "Request_ResourceNotFound", status: http.StatusNotFound},
	} {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			calls := 0
			c := &client{provider: &groupMembershipTestProvider{add: func(ctx context.Context, group, member string) error {
				require.NoError(t, ctx.Err())
				require.Equal(t, "member", member)
				calls++
				if calls <= 2 {
					require.Equal(t, "first", group)
				} else {
					require.Equal(t, "second", group)
				}
				if calls == 1 {
					return groupMembershipTestError(tc.code, tc.status)
				}
				return nil
			}}}
			require.NoError(t, c.addGroupMemberships(context.Background(), "member",
				[]*AzureGroup{{ObjectID: "first"}, {ObjectID: "second"}}))
			require.Equal(t, 3, calls)
		})
	}
}

// TestAddGroupMembershipsFailure verifies that failures stop at the first group,
// keep the caller's deadline, and include the Graph error.
func TestAddGroupMembershipsFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code       string
		cancel     bool
		wantCtxErr error
	}{
		{name: "persistent denial", code: "Authorization_RequestDenied", wantCtxErr: context.DeadlineExceeded},
		{name: "cancellation", code: "Authorization_RequestDenied", cancel: true, wantCtxErr: context.Canceled},
		{name: "unrelated error", code: "OtherError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			graphErr := groupMembershipTestError(tc.code, http.StatusForbidden)
			calls := 0
			c := &client{provider: &groupMembershipTestProvider{add: func(callCtx context.Context, _, _ string) error {
				calls++
				deadline, ok := callCtx.Deadline()
				require.True(t, ok)
				parentDeadline, _ := ctx.Deadline()
				require.Equal(t, parentDeadline, deadline)
				if tc.cancel {
					cancel()
				}
				return graphErr
			}}}
			err := c.addGroupMemberships(ctx, "member", []*AzureGroup{{ObjectID: "first"}, {ObjectID: "second"}})
			require.ErrorIs(t, err, graphErr)
			require.Equal(t, 1, calls)
			if tc.wantCtxErr != nil {
				require.ErrorIs(t, err, tc.wantCtxErr)
			} else {
				require.NotErrorIs(t, err, context.DeadlineExceeded)
			}
		})
	}
}

// TestAddGroupMembershipsBudget verifies that each group gets its own 80-second
// timeout when the caller has no deadline, and that a caller deadline is kept.
func TestAddGroupMembershipsBudget(t *testing.T) {
	groups := []*AzureGroup{{ObjectID: "first"}, {ObjectID: "second"}}

	t.Run("no caller deadline", func(t *testing.T) {
		start := time.Now()
		var contexts []context.Context
		c := &client{provider: &groupMembershipTestProvider{add: func(callCtx context.Context, _, _ string) error {
			deadline, ok := callCtx.Deadline()
			require.True(t, ok)
			require.WithinDuration(t, start.Add(retryTimeout), deadline, time.Second)
			if len(contexts) == 1 {
				require.ErrorIs(t, contexts[0].Err(), context.Canceled, "each group must release its own timeout")
				require.NoError(t, callCtx.Err(), "the next group must receive a fresh timeout")
			}
			contexts = append(contexts, callCtx)
			return nil
		}}}
		require.NoError(t, c.addGroupMemberships(context.Background(), "member", groups))
		require.Len(t, contexts, 2)
		require.ErrorIs(t, contexts[1].Err(), context.Canceled)
	})

	t.Run("caller deadline longer than default", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*retryTimeout)
		defer cancel()
		parentDeadline, _ := ctx.Deadline()
		calls := 0
		c := &client{provider: &groupMembershipTestProvider{add: func(callCtx context.Context, _, _ string) error {
			calls++
			deadline, ok := callCtx.Deadline()
			require.True(t, ok)
			require.Equal(t, parentDeadline, deadline, "preserve the caller's deadline even when longer than 80 seconds")
			return nil
		}}}
		require.NoError(t, c.addGroupMemberships(ctx, "member", groups))
		require.Equal(t, 2, calls)
		require.NoError(t, ctx.Err())
	})
}

// TestAddGroupMembershipsCanceledRequest verifies that Azure is not called when
// the request is already canceled.
func TestAddGroupMembershipsCanceledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &client{provider: &groupMembershipTestProvider{add: func(context.Context, string, string) error {
		t.Fatal("canceled request called Azure")
		return nil
	}}}
	require.ErrorIs(t, c.addGroupMemberships(ctx, "member", []*AzureGroup{{ObjectID: "group"}}), context.Canceled)
}

// TestAddGroupMembershipsSuccessDuringCancellation verifies that a successful
// Graph write is trusted even if the request is canceled at the same time.
func TestAddGroupMembershipsSuccessDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &client{provider: &groupMembershipTestProvider{add: func(callCtx context.Context, _, _ string) error {
		require.NoError(t, callCtx.Err())
		cancel()
		return nil
	}}}
	require.NoError(t, c.addGroupMemberships(ctx, "member", []*AzureGroup{{ObjectID: "group"}}))
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}

// TestAddGroupMembershipsInFlightDeadline verifies that a deadline reached
// during a Graph call is returned as a deadline error.
func TestAddGroupMembershipsInFlightDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c := &client{provider: &groupMembershipTestProvider{add: func(callCtx context.Context, _, _ string) error {
		<-callCtx.Done()
		return callCtx.Err()
	}}}
	require.ErrorIs(t, c.addGroupMemberships(ctx, "member", []*AzureGroup{{ObjectID: "group"}}), context.DeadlineExceeded)
}

// TestAddGroupMembershipsLastError verifies that only the most recent Graph
// error is returned, whether retries stop on cancellation or a terminal error.
func TestAddGroupMembershipsLastError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tc := range []struct {
		name         string
		lastCode     string
		wantCanceled bool
	}{
		{name: "retryable error then canceled", lastCode: "Authorization_RequestDenied", wantCanceled: true},
		{name: "terminal error", lastCode: "OtherError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := groupMembershipTestError("Request_ResourceNotFound", http.StatusNotFound)
			last := groupMembershipTestError(tc.lastCode, http.StatusForbidden)
			calls := 0
			c := &client{provider: &groupMembershipTestProvider{add: func(context.Context, string, string) error {
				calls++
				if calls == 1 {
					return first
				}
				if tc.wantCanceled {
					cancel()
				}
				return last
			}}}
			err := c.addGroupMemberships(ctx, "member", []*AzureGroup{{ObjectID: "group"}})
			require.Equal(t, 2, calls)
			require.ErrorIs(t, err, last)
			require.NotErrorIs(t, err, first)
			if tc.wantCanceled {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

// TestAddGroupMembershipsAuthorizationBudget verifies that the first
// authorization denial starts a 30-second window that later errors do not restart.
func TestAddGroupMembershipsAuthorizationBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tc := range []struct {
		subsequentCode   string
		subsequentStatus int
	}{
		{subsequentCode: "Authorization_RequestDenied", subsequentStatus: http.StatusForbidden},
		{subsequentCode: "Request_ResourceNotFound", subsequentStatus: http.StatusNotFound},
	} {
		t.Run(tc.subsequentCode, func(t *testing.T) {
			t.Parallel()
			first := groupMembershipTestError("Authorization_RequestDenied", http.StatusForbidden)
			last := groupMembershipTestError(tc.subsequentCode, tc.subsequentStatus)
			calls := 0
			var firstDenied time.Time
			var limitedDeadline time.Time
			c := &client{provider: &groupMembershipTestProvider{add: func(ctx context.Context, _, _ string) error {
				calls++
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				if calls == 1 {
					firstDenied = time.Now()
					require.Greater(t, time.Until(deadline), groupAuthorizationRetryTimeout)
					return first
				}
				require.WithinDuration(t, firstDenied.Add(groupAuthorizationRetryTimeout), deadline, time.Second)
				if limitedDeadline.IsZero() {
					limitedDeadline = deadline
				} else {
					require.Equal(t, limitedDeadline, deadline, "authorization window must not restart")
				}
				return last
			}}}
			err := c.addGroupMemberships(context.Background(), "member", []*AzureGroup{{ObjectID: "group"}})
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorIs(t, err, last)
			require.Greater(t, calls, 1)
			require.WithinDuration(t, firstDenied.Add(groupAuthorizationRetryTimeout), time.Now(), time.Second)
		})
	}
}
