// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestNewHTTPClient(t *testing.T) {
	for _, tc := range []struct {
		Name    string          // Name of the test case
		Logger  hclog.Logger    // Logger to use (should be nil or [FakeLogger])
		Timeout []time.Duration // Timeout argument is optional (variadic)
	}{
		{
			Name:    "LoggerNil_TimeoutUnset",
			Logger:  nil,
			Timeout: nil,
		},
		{
			Name:    "FakeLogger_TimeoutUnset",
			Logger:  NewFakeLogger(),
			Timeout: nil,
		},
		{
			Name:    "FakeLogger_TimeoutZero",
			Logger:  NewFakeLogger(),
			Timeout: []time.Duration{0},
		},
		{
			Name:    "FakeLogger_TimeoutNegative",
			Logger:  NewFakeLogger(),
			Timeout: []time.Duration{-time.Second},
		},
		{
			Name:    "FakeLogger_TimeoutPositive",
			Logger:  NewFakeLogger(),
			Timeout: []time.Duration{time.Minute},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			var ok bool
			var wt *WrappedTransport
			var client *http.Client

			// Ensure we can construct the [http.Client] and that we can
			// type assert the [WrappedTransport] to a non-nil pointer.
			if !assert.NotPanics(t, func() {
				client = NewHTTPClient(tc.Logger, tc.Timeout...)
			}) {
				return
			} else if !assert.NotNil(t, client) {
				return
			} else if wt, ok = client.Transport.(*WrappedTransport); !assert.True(
				t, ok, "%T.Transport should be %T (have %T)",
				client, wt, client.Transport,
			) {
				return
			} else if !assert.NotNil(
				t, wt, "%T.Transport should not be a nil %T",
				client, wt,
			) {
				return
			}

			// Ensure [WrappedTransport.logger] is what we expect it to be.
			if !assert.NotNil(
				t, wt.logger, "%T.logger should never be nil",
				client,
			) {
				return
			} else if tc.Logger != nil && !assert.Same(
				t, tc.Logger, wt.logger,
				"%T.logger: should be same %T provided to constructor",
				client, wt,
			) {
				return
			} else if tc.Logger == nil && !assert.Same(
				t, noopLogger, wt.logger,
				"%T.logger: should use noop %T when nil logger given to constructor",
				client, wt.logger,
			) {
				return
			}

			// Ensure we handled the timeout argument correctly.
			if len(tc.Timeout) == 0 {
				if !assert.Zero(
					t, client.Timeout,
					"%T.Timeout: constructor never received timeout arg",
				) {
					return
				}
			} else if tc.Timeout[0] < 1 {
				if !assert.Zero(
					t, client.Timeout,
					"%T.Timeout: constructor should not use values <= 0",
					client,
				) {
					return
				}
			} else if !assert.Equal(
				t, tc.Timeout[0], client.Timeout,
				"%T.Timeout: constructor should use supplied argument",
				client,
			) {
				return
			}
		})
	}
}

func TestGetRequestStorage(t *testing.T) {
	t.Run("NotPresent", func(t *testing.T) {
		ctx := context.Background()
		rs, ok := GetRequestStorage(ctx)

		assert.Nil(t, rs, "%T value", rs)
		assert.False(t, ok, "ok value")
	})

	t.Run("Present", func(t *testing.T) {
		ctx := context.WithValue(
			context.Background(),
			keyRequestStorage,
			&RequestStorage{Serial: 1234},
		)

		rs, ok := GetRequestStorage(ctx)

		_ = assert.NotNil(t, rs, "%T value", rs) &&
			assert.True(t, ok, "ok value") &&
			assert.Equal(t, uint64(1234), rs.Serial, "value for %T.Serial", rs)
	})
}

func TestRequestStorage(t *testing.T) {
	t.Run("Elapsed", func(t *testing.T) {
		t.Run("NotStarted", func(t *testing.T) {
			var rs RequestStorage
			assert.Zero(t, rs.Elapsed())
		})

		t.Run("StartedNotDone", func(t *testing.T) {
			var rs RequestStorage
			rs.Start = time.Now().Add(-time.Second)
			assert.GreaterOrEqual(t, rs.Elapsed(), time.Second)
		})

		t.Run("StartedAndDone", func(t *testing.T) {
			var rs RequestStorage
			rs.End = time.Now()
			rs.Start = rs.End.Add(-500432 * time.Microsecond)
			assert.Equal(t, rs.Elapsed(time.Millisecond), 500*time.Millisecond)
		})
	})
}

func TestWrapTransport(t *testing.T) {
	t.Run("NilClient", func(t *testing.T) {
		assert.ErrorIs(t, WrapTransport(nil, nil), ErrNil)
	})

	t.Run("NilTransport", func(t *testing.T) {
		var c http.Client

		if assert.NoError(t, WrapTransport(&c, nil)) {
			assert.NotNil(t, c.Transport)
		}
	})

	t.Run("AlreadyWrapped", func(t *testing.T) {
		c := NewHTTPClient(nil)
		orig := c.Transport.(*WrappedTransport)
		if assert.NoError(t, WrapTransport(c, nil)) {
			assert.Same(t, orig, c.Transport.(*WrappedTransport))
		}
	})
}

func TestWrappedTransport(t *testing.T) {
	var events []*FakeLogRecord
	cleanupEvents := func() { events = nil }

	logger := &FakeLogger{
		Notify: func(rec *FakeLogRecord) (keep bool) {
			events = append(events, rec)
			return keep
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /success", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "success"}`))
	})

	mux.HandleFunc("GET /graph-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(graphErrorBody))
	})

	mux.HandleFunc("GET /server-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error": "service unavailable"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, err := url.Parse(srv.URL)
	if !assert.NoError(t, err, "should be able to parse test server URL") {
		return
	}

	client := NewHTTPClient(logger)

	t.Run("RoundTrip", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			defer cleanupEvents()
			resp, err := client.Get(baseURL.String() + "/success")
			if !assert.NoError(t, err) {
				return
			}

			rs, ok := GetRequestStorage(resp.Request.Context())
			if !assert.NotNil(t, rs, "request context should have %T present", rs) {
				return
			} else if !assert.True(t, ok, "should have %T", rs) {
				return
			}

			expectLogPairs := map[string]any{
				"transport_id": rs.Serial,
				"host":         baseURL.Host,
				"path":         "/success",
				"method":       http.MethodGet,
			}

			if !assert.Len(t, events, 2, "should have 2 logging events") {
				return
			} else if !events[0].Assert(t, hclog.Trace, "initialized request", expectLogPairs) {
				return
			}

			expectLogPairs["status_code"] = http.StatusOK
			expectLogPairs["elapsed"] = nil // just want to make sure its present
			events[1].Assert(t, hclog.Trace, "request finished", expectLogPairs)
			resp.Body.Close()
		})

		t.Run("GraphError", func(t *testing.T) {
			defer cleanupEvents()
			resp, err := client.Get(baseURL.String() + "/graph-error")
			if !assert.NoError(t, err) {
				return
			}

			rs, ok := GetRequestStorage(resp.Request.Context())
			if !assert.NotNil(t, rs, "request context should have %T present", rs) {
				return
			} else if !assert.True(t, ok, "should have %T", rs) {
				return
			} else if !assert.NotNil(t, rs.Err, "%T.Err should be set", rs) {
				return
			} else if body, err := io.ReadAll(resp.Body); !assert.NoError(
				t, err,
				"failed to read body",
			) {
				return
			} else if !assert.Equal(
				t, graphErrorBody, string(body),
				"intercepted response body should be a perfect copy",
			) {
				return
			}

			expectLogPairs := map[string]any{
				"transport_id": rs.Serial,
				"host":         baseURL.Host,
				"path":         "/graph-error",
				"method":       http.MethodGet,
			}

			if !assert.Len(t, events, 2, "should have 2 logging events") {
				return
			} else if !events[0].Assert(t, hclog.Trace, "initialized request", expectLogPairs) {
				return
			}

			maps.Copy(expectLogPairs, map[string]any{
				"code":              ErrorCode("Authorization_RequestDenied"),
				"status_code":       http.StatusForbidden,
				"target":            "foo",
				"client_request_id": "b34fed20-a4f2-439d-b819-3f14aa646701",
				"request_id":        "b34fed20-a4f2-439d-b819-3f14aa646701",
				"type":              "bar",
				"elapsed":           nil, // just want to make sure its present
			})

			events[1].Assert(t, hclog.Trace, "graph error response", expectLogPairs)
			resp.Body.Close()
		})
	})
}

const graphErrorBody = `{
    "error": {
        "code": "Authorization_RequestDenied",
        "message": "When using this permission, the backing application of the service principal being created must in the local tenant",
		"target": "foo",
        "innerError": {
			"@odata.type": "bar",
            "date": "1999-12-31T23:59:59",
            "request-id": "b34fed20-a4f2-439d-b819-3f14aa646701",
            "client-request-id": "b34fed20-a4f2-439d-b819-3f14aa646701"
        }
    }
}`
