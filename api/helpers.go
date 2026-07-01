package api

import (
	"maps"
	"net/http"
	"strconv"
	"time"

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
