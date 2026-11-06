// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
)

// WrappedTransport wraps an [http.Transport], implementing [http.RoundTripper]
// to provide entry and exit hooks for inflight requests.
//
// Currently, it will
//
//   - ensure that a [RequestStorage] is present in the [context.Context]
//     returned by the inflight request's [http.Request.Context].
//   - emit log record just before starting the request (trace)
//   - emit log record when receiving a response (trace)
//   - transparently intercept, deserialize, and log Graph API errors as
//     [Error] objects
//
// See also: [GetRequestStorage] to retrieve the request-local storage.
type WrappedTransport struct {
	wrap   http.RoundTripper
	logger hclog.Logger
	serial atomic.Uint64
}

// RequestStorage provides local storage valid for the lifetime of a request.
//
// This data structure is automatically placed into the [context.Context]
// of an [http.Request] when using a [WrappedTransport], which implements
// [http.RoundTripper].
type RequestStorage struct {
	// Serial is an atomically incremented integer (local to the originating
	// [WrappedTransport]) identifying the request.
	Serial uint64

	// Start of the request.
	Start time.Time

	// End of the request (zero value when in progress).
	End time.Time

	// Logger containing request/response pairs.
	Logger hclog.Logger

	// Err holds the last [Error] to have occurred. It is opportunistically
	// populated if an [http.Response] with a status code >= 400 is received.
	Err *Error
}

// ============================================================================
// |                            [WrappedTransport]                            |
// ============================================================================

// NewHTTPClient returns a new [http.Client] (via the "cleanhttp" package)
// which is wrapped via [WrapTransport].
//
// If provided, timeout specifies a time limit for requests made by the
// [http.Client].
//
// This function always succeeds.
func NewHTTPClient(logger hclog.Logger, timeout ...time.Duration) (c *http.Client) {
	if c = cleanhttp.DefaultClient(); len(timeout) > 0 && timeout[0] >= 0 && timeout[0] != c.Timeout {
		c.Timeout = timeout[0]
	}

	if err := WrapTransport(c, logger); err != nil {
		panic(err)
	}

	return c
}

// WrapTransport wraps the [http.RoundTripper] present on the given
// [http.Client] if it is not already wrapped by a [WrappedTransport].
//
// This function will return an error identifying as [ErrNil] if the given
// [http.Client] is nil. Otherwise, this function always succeeds.
func WrapTransport(c *http.Client, logger hclog.Logger) error {
	var rt http.RoundTripper

	if c == nil {
		return fmt.Errorf("%w %T", ErrNil, c)
	} else if _, ok := c.Transport.(*WrappedTransport); ok {
		return nil // no-op (already wrapped)
	} else if rt = c.Transport; rt == nil {
		rt = cleanhttp.DefaultTransport()
	}

	c.Transport = &WrappedTransport{
		wrap:   rt,
		logger: SafeLogger(logger),
	}

	return nil
}

// RoundTrip implements [http.RoundTripper] for [WrappedTransport].
func (t *WrappedTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	var rs RequestStorage

	rs.Serial = t.serial.Add(1)
	rs.Logger = t.logger.With(
		"transport_id", rs.Serial,
		"host", req.URL.Host,
		"path", req.URL.Path,
		"method", req.Method,
	)

	ctx := context.WithValue(req.Context(), keyRequestStorage, &rs)
	rs.Logger.Trace("initialized request")

	rs.Start = time.Now()
	resp, err = t.wrap.RoundTrip(req.WithContext(ctx))
	rs.End = time.Now()
	elapsed := rs.Elapsed(time.Millisecond).String()

	if err != nil {
		t.logger.Error(
			"transport error",
			"elapsed", elapsed,
			"error", err,
		)
	} else if rs.Err, err = tryAutoDecodeError(resp); err != nil {
		rs.Logger.Error(
			"failed to decode graph error",
			"error", err,
			"elapsed", elapsed,
			"status_code", resp.StatusCode,
		)
	} else if rs.Err != nil {
		rs.Logger.Trace(
			"graph error response",
			slices.Concat(
				[]any{
					"elapsed", elapsed,
					"error", rs.Err.Error(),
				},
				rs.Err.LoggerPairs(),
			)...,
		)
	} else {
		rs.Logger.Trace(
			"request finished",
			"elapsed", elapsed,
			"status_code", resp.StatusCode,
		)
	}

	return resp, err
}

// Unwrap returns the [http.RoundTripper] being wrapped.
func (t *WrappedTransport) Unwrap() http.RoundTripper { return t.wrap }

// ============================================================================
// |                             [RequestStorage]                             |
// ============================================================================

// GetRequestStorage returns the [RequestStorage] data from the given context.
// A [RequestStorage] object is only present in a [context.Context] originating
// from an [http.Request] handled by a [WrappedTransport].
func GetRequestStorage(ctx context.Context) (rs *RequestStorage, ok bool) {
	rs, ok = ctx.Value(keyRequestStorage).(*RequestStorage)
	return rs, ok
}

func (rs *RequestStorage) Elapsed(round ...time.Duration) (dur time.Duration) {
	if rs.Start.IsZero() {
		return dur
	} else if rs.End.IsZero() {
		dur = time.Since(rs.Start)
	} else {
		dur = rs.End.Sub(rs.Start)
	}

	if len(round) > 0 && round[0] > 1 {
		dur = dur.Round(round[0])
	}

	return dur
}

// ============================================================================
// |                     Unexported / uninteresting stuff                     |
// ============================================================================

type contextKey uint

const keyRequestStorage = contextKey(iota + 1)

type bufferWithClose struct {
	bytes.Buffer
}

func (b *bufferWithClose) Close() error {
	b.Buffer.Reset()
	return nil
}

// tryAutoDecodeError tries to unmarshal an [Error] from the [http.Response],
// but only if the [http.Response.StatusCode] is >= 400, returning a non-nil
// [Error] on success.
//
// The [error] will be non-nil if attempting to read the response body fails
// in any way. In this event, the pointer to the [Error] is nil.
func tryAutoDecodeError(resp *http.Response) (*Error, error) {
	var buf bufferWithClose

	// we don't want to interfere with other downstream consumers of the
	// response body, so we'll copy and replace the current value, and use
	// [bytes.Buffer.Bytes] to peek without consuming when trying to decode.
	if resp == nil || resp.StatusCode < 400 {
		return nil, nil // nothing to do
	} else if n, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	} else if err = resp.Body.Close(); err != nil {
		return nil, err
	} else if resp.Body = &buf; n == 0 {
		return nil, nil
	}

	type errorBody struct {
		Error *Error `json:"error"`
	}

	var eb errorBody
	if json.Unmarshal(buf.Bytes(), &eb) == nil {
		// We don't care about the unmarshaling error, since this is an
		// opportunistic parser. If it fails to parse, it's not an [Error].
		eb.Error.ResponseInfo = &ErrorResponseInfo{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header.Clone(),
		}

		eb.Error.ResponseInfo.RetryAfter = TryParseRetryAfter(eb.Error.ResponseInfo.Headers)
	}

	return eb.Error, nil
}
