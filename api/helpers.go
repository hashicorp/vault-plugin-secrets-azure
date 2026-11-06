// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/go-hclog"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/serialization"
)

// Deref safely dereferences the given pointer, returning the zero value of T
// if nil.
func Deref[T any](ptr *T) T {
	var zero T

	if ptr != nil {
		return *ptr
	}

	return zero
}

// IsDigit indicates if the given string or bytestring is comprised of only
// ASCII digits, possibly prefixed by a +/- sign.
func IsDigit[T ~string | ~[]byte](s T) bool {
	var i int

	if len(s) == 0 {
		return false
	} else if len(s) > 1 && (s[0] == '+' || s[0] == '-') {
		i++
	}

	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

// CopyHeaders copies the HTTP headers from the given [abstractions.ResponseHeaders].
// If nil or empty, the result is a nil [http.Header] object.
//
// This function canonicalizes all header names via [http.CanonicalHeaderKey].
func CopyHeaders(headers *abstractions.ResponseHeaders) (out http.Header) {
	if headers == nil {
		return nil
	} else if keys := headers.ListKeys(); len(keys) > 0 {
		out = make(http.Header, len(keys))
		for i := range keys {
			out[http.CanonicalHeaderKey(keys[i])] = headers.Get(keys[i])
		}
	}

	return out
}

// CopyAdditionalData uses [maps.Clone] to clone the additional data present in
// the given data holder, if possible. Otherwise, it returns nil.
func CopyAdditionalData(v serialization.AdditionalDataHolder) (data map[string]any) {
	if v != nil {
		data = maps.Clone(v.GetAdditionalData())
	}

	return data
}

// SafeLogger returns the same [hclog.Logger] if the argument is not nil,
// otherwise it returns a no-op [hclog.Logger].
//
// This function should be preferred over [hclog.NewNullLogger], as the
// [hclog.Logger] returned by the latter may panic when the result is
// followed with a call to the [hclog.Logger.With] method.
func SafeLogger(logger hclog.Logger) hclog.Logger {
	if logger != nil {
		return logger
	}

	return noopLogger
}

// TryParseRetryAfter is a best-effort function which parses the value of the
// "Retry-After" header into a [time.Time]. The header value should be present
// as either
//
//   - a non-negative integer representing the number of seconds to wait from
//     either the current or optionally speciifed time
//   - a date string in [time.RFC1123] format. If an optional start time is
//     specified, it is ignored.
//
// On success, returns a non-nil [time.Time] indicating when to retry.
func TryParseRetryAfter(headers http.Header, whence ...time.Time) *time.Time {
	if values := headers.Values("Retry-After"); len(values) == 0 || values[0] == "" {
		return nil
	} else if IsDigit(values[0]) {
		var start time.Time

		if len(whence) == 0 {
			start = time.Now()
		} else {
			start = whence[0]
		}

		if seconds, err := strconv.ParseInt(values[0], 10, 64); err == nil && seconds > -1 {
			return new(start.Add(time.Duration(seconds) * time.Second))
		}

	} else if t, err := time.Parse(time.RFC1123, values[0]); err == nil {
		return new(t)
	}

	return nil
}

// ParseNaiveISO8601Time normalizes and parses a string which resembles an
// ISO-8601 (or RFC-3339) formatted timestamp, but is possibly missing its
// timezone.
//
// If a timezone is missing, this function will append the optionally supplied
// default timezone, which defaults to "Z" (UTC) if not given.
//
// Once normalized, the string is parsed using [time.Parse] with a layout of
// [time.RFC3339Nano].
func ParseNaiveISO8601Time(s string, defaultTimezone ...string) (time.Time, error) {
	var needTz bool
	var fracEnd int
	var tz string

	if tz = "Z"; len(defaultTimezone) > 0 && defaultTimezone[0] != "" {
		tz = defaultTimezone[0]
	}

	// Minimal (len=19): "2006-01-02T15:04:05"
	// Maximal (len=38): "2006-01-02T15:04:05.999999999Z07:00:00"

	if n := len(s); n == 19 {
		needTz = true
	} else if n > 19 && n <= 38 && s[19] == '.' {
		for fracEnd = 20; fracEnd < len(s); fracEnd++ {
			if s[fracEnd] < '0' || s[fracEnd] > '9' {
				break
			}
		}

		needTz = fracEnd == n
	}

	if needTz {
		s += tz
	}

	return time.Parse(time.RFC3339Nano, s)
}

// ============================================================================
// |                     Unexported / uninteresting stuff                     |
// ============================================================================

const (
	keyOptional = 1 << iota
	zeroMissing
	zeroOnError
)

// readKeyTo retrieves the value of the key from the given map and attempts to
// assign it to the location pointed at by dst.
//
// Consumes an optional argument, a bitmask which controls function behavior:
//
//   - [keyOptional] -- do not consider it an error if the key is not present
//     in the map.
//   - [zeroMissing] -- when [keyOptional] is set and the key is not present,
//     set the destination pointer to the zero value of T.
//   - [zeroOnError] -- when an error occurs, set the destination pointer to
//     the zero value of T.
//
// An error may occur under any of the following conditions:
//
//   - The destination pointer is nil. Returns an error identifying as [ErrNil].
//   - The [keyOptional] bit is not set (the default) and the key is not present
//     in the source map. Returns an error identifying as [ErrNotFound].
//   - The key was found in the map, but it is not of type T. Returns an error
//     explaining the type discrepancy, but does not identify as any specific
//     base error.
func readKeyTo[K comparable, T any](src map[K]any, key K, dst *T, opts ...uint) (err error) {
	if mode := cmp.Or(opts...); dst == nil {
		err = fmt.Errorf("key %v: dst %T cannot be %w", key, dst, ErrNil)
	} else if raw, present := src[key]; !present {
		if mode&keyOptional == keyOptional {
			setZeroWhen(dst, mode&zeroMissing == zeroMissing)
		} else {
			err = fmt.Errorf("key %v: %w", key, ErrNotFound)
			setZeroWhen(dst, mode&zeroOnError == zeroOnError)
		}
	} else if val, ok := raw.(T); !ok {
		err = fmt.Errorf("key %v: expected type %T (got %T)", key, *dst, raw)
		setZeroWhen(dst, mode&zeroOnError == zeroOnError)
	} else {
		*dst = val
	}

	return err
}

// setZeroWhen sets the destination pointed to by dst to the zero value of T
// when the predicate is true, otherwise does nothing.
func setZeroWhen[T any](dst *T, predicate bool) {
	var zero T

	if predicate {
		*dst = zero
	}
}

// kiotaNeverRetry is used as the [khttp.RetryHandlerOptions.ShouldRetry] field
// value so that the [http.Client] powering a [MSGraphClient] never attempts to
// retry failed requests.
func kiotaNeverRetry(_ time.Duration, _ int, _ *http.Request, _ *http.Response) bool {
	return false
}

// ============================================================================
// |                               Logger stuff                               |
// ============================================================================

// noopLogger never logs anything. Used by [SafeLogger]
var noopLogger = hclog.New(&hclog.LoggerOptions{
	Level:             hclog.Off,
	Output:            io.Discard,
	Mutex:             (*noopLocker)(nil),
	IndependentLevels: true,
	DisableTime:       true,
	Exclude:           alwaysExcludeLog,
})

// alwaysExcludeLog always indicates a value should not be logged.
func alwaysExcludeLog(_ hclog.Level, _ string, _ ...any) bool { return true }

// noopLocker is a no-op [sync.Locker] implementation whose nil receiver never
// panics.
type noopLocker struct{}

func (*noopLocker) Lock()   {}
func (*noopLocker) Unlock() {}
