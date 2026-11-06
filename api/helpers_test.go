// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/stretchr/testify/assert"
)

func TestDeref(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var ptr *string
		assert.NotPanics(t, func() { assert.Equal(t, "", Deref(ptr)) })
	})

	t.Run("NonNil", func(t *testing.T) {
		expect := "fooBarBaz"
		assert.Equal(t, expect, Deref(&expect))
	})
}

func TestCopyHeaders(t *testing.T) {
	for _, tc := range []struct {
		Name   string // test name
		In     *abstractions.ResponseHeaders
		Expect http.Header
	}{
		{
			Name:   "Nil",
			In:     nil,
			Expect: nil,
		},
		{
			Name:   "Empty",
			In:     new(abstractions.ResponseHeaders),
			Expect: nil,
		},
		{
			Name: "SingleValuedHeaders",
			In: new(kiotaHeaderBuilder).
				With("content-type", "application/json").
				With("x-foo", "bar").
				Build(),
			Expect: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Foo":        []string{"bar"},
			},
		},
		{
			Name: "MultiValuedHeaders",
			In: new(kiotaHeaderBuilder).
				With("retry-after", "100").
				With("x-foo", "bar", "baz", "qux").
				Build(),
			Expect: http.Header{
				"Retry-After": []string{"100"},
				"X-Foo":       []string{"bar", "baz", "qux"},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			// inform of improper test params
			for k := range tc.Expect {
				if expectKey := http.CanonicalHeaderKey(k); k != expectKey {
					panic(
						fmt.Sprintf(
							"bad test params: http.Header keys must be "+
								"canonicalized (got %q, expected %q)",
							k, expectKey,
						),
					)
				}
			}

			actual := CopyHeaders(tc.In)
			if len(tc.Expect) == 0 {
				assert.Nil(t, actual)
				return
			}

			keys := tc.In.ListKeys()
			if !assert.Len(t, actual, len(keys)) {
				return
			}

			for i := range keys {
				expectKey := http.CanonicalHeaderKey(keys[i])
				actualValues, ok := actual[expectKey]

				if !assert.True(
					t, ok, "missing canonicalized key %q (original key %q)",
					expectKey, keys[i],
				) {
					return
				}

				// multivalued kiota response headers are (currently) unordered,
				// so make sure sides of the assertion are in the same order.
				slices.Sort(actualValues)
				slices.Sort(tc.Expect[expectKey])

				assert.Equal(
					t, tc.Expect[expectKey], actualValues,
					"unexpected content for key %q",
					expectKey,
				)
			}
		})
	}
}

func TestIsDigit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		digit bool
	}{
		{name: "Empty", input: "", digit: false},
		{name: "BadMultiDigitHex", input: "0123456789abcdef", digit: false},
		{name: "BadOnlySignPlus", input: "+", digit: false},
		{name: "BadOnlySignMinus", input: "-", digit: false},
		{name: "BadSignEnd", input: "2+", digit: false},
		{name: "BadSignMid", input: "2-1", digit: false},
		{name: "SingleDigit", input: "1", digit: true},
		{name: "SingleDigitPlus", input: "+3", digit: true},
		{name: "SingleDigitMinus", input: "-4", digit: true},
		{name: "MultiDigit", input: "0123456789", digit: true},
		{name: "MultiDigitPlus", input: "+0123456789", digit: true},
		{name: "MultiDigitMinus", input: "-0123456789", digit: true},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.digit, IsDigit(tc.input)) })
	}
}

func TestTryParseRetryAfter(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		assert.Nil(t, TryParseRetryAfter(nil))
	})

	t.Run("Empty", func(t *testing.T) {
		headers := http.Header{"Retry-After": []string{}}
		assert.Nil(t, TryParseRetryAfter(headers))
	})

	t.Run("Junk", func(t *testing.T) {
		headers := http.Header{"Retry-After": []string{"foo"}}
		assert.Nil(t, TryParseRetryAfter(headers))
	})

	t.Run("Seconds", func(t *testing.T) {
		headers := http.Header{"Retry-After": []string{"120"}}
		start := time.Now().UTC()
		after := TryParseRetryAfter(headers)
		drift := time.Since(start)

		if !assert.NotNil(t, after, "should parse positive integer duration") {
			return
		}

		result := (after.Sub(start) - drift).Round(time.Second)
		assert.Equal(t, 120*time.Second, result)
	})

	t.Run("RFC1123Date", func(t *testing.T) {
		start := time.Now().UTC().Truncate(time.Second)
		until := start.Add(120 * time.Second)
		headers := http.Header{"Retry-After": []string{until.Format(time.RFC1123)}}
		result := TryParseRetryAfter(headers)

		if !assert.NotNil(t, result, "should parse RFC1123 formatted date") {
			return
		}

		assert.Equal(t, 120*time.Second, result.Sub(start))
	})
}

func TestParseNaiveISO8601Time(t *testing.T) {
	const fullRFC3339 = "2006-01-02T15:04:05.000000000Z07:00"
	for _, tc := range []struct {
		Name        string
		Input       string
		Zone        []string
		Expect      time.Time
		ExpectError bool
	}{
		{
			Name:        "Empty",
			Input:       "",
			ExpectError: true,
		},
		{
			Name:        "Malformed",
			Input:       "1999-12-31T23:59:59.",
			ExpectError: true,
		},
		{
			Name:   "Aware_Seconds",
			Input:  "1999-12-31T23:59:59Z",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			Name:   "Aware_Milliseconds",
			Input:  "1999-12-31T23:59:59.999Z",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, int(999*time.Millisecond), time.UTC),
		},
		{
			Name:   "Naive_Seconds",
			Input:  "1999-12-31T23:59:59",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			Name:   "Naive_Seconds_ExplicitZone",
			Input:  "1999-12-31T23:59:59",
			Zone:   []string{"+00:00"},
			Expect: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			Name:   "Naive_Deciseconds",
			Input:  "1999-12-31T23:59:59.1",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, int(time.Second)/10, time.UTC),
		},
		{
			Name:   "Naive_Centiseconds",
			Input:  "1999-12-31T23:59:59.01",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, int(time.Second)/100, time.UTC),
		},
		{
			Name:   "Naive_Microseconds",
			Input:  "1999-12-31T23:59:59.000001",
			Expect: time.Date(1999, 12, 31, 23, 59, 59, int(time.Second)/1_000_000, time.UTC),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tm, err := ParseNaiveISO8601Time(tc.Input, tc.Zone...)
			if tc.ExpectError {
				assert.Error(t, err)
				return
			}

			_ = assert.NoError(t, err) &&
				assert.Equal(t, tc.Expect.Format(fullRFC3339), tm.Format(fullRFC3339))
		})
	}
}

func TestReadKeyTo(t *testing.T) {
	t.Run("NilPointer", func(t *testing.T) {
		var dst *int
		assertReadKey(t, map[string]any{}, "foo", dst, 0)
	})

	t.Run("Required", func(t *testing.T) {
		t.Run("KeyPresent", func(t *testing.T) {
			t.Run("Valid", func(t *testing.T) {
				var dst int
				assertReadKey(t, map[string]any{"foo": 42}, "foo", &dst, 0)
				assert.Equal(t, 42, dst, "value should have changed")
			})

			t.Run("BadType", func(t *testing.T) {
				t.Run("NoZeroOnError", func(t *testing.T) {
					dst := 42
					assertReadKey(t, map[string]any{"foo": "not a number"}, "foo", &dst, 0)
					assert.Equal(t, 42, dst, "value should not change on error")
				})

				t.Run("ZeroOnError", func(t *testing.T) {
					dst := 42
					assertReadKey(t, map[string]any{"foo": "not a number"}, "foo", &dst, zeroOnError)
					assert.Zero(t, dst, "value should have been zeroed on error")
				})
			})
		})

		t.Run("KeyMissing", func(t *testing.T) {
			t.Run("NoZeroOnError", func(t *testing.T) {
				dst := 42
				assertReadKey(t, map[string]any{}, "foo", &dst, 0)
				assert.Equal(t, 42, dst, "value should not change on error")
			})

			t.Run("ZeroOnError", func(t *testing.T) {
				dst := 42
				assertReadKey(t, map[string]any{}, "foo", &dst, zeroOnError)
				assert.Zero(t, dst, "value should have been zeroed on error")
			})
		})
	})

	t.Run("Optional", func(t *testing.T) {
		t.Run("KeyMissing", func(t *testing.T) {
			t.Run("NoZeroMissing", func(t *testing.T) {
				dst := 42
				assertReadKey(t, map[string]any{}, "foo", &dst, keyOptional)
				assert.Equal(t, 42, dst, "value should not change on error")
			})

			t.Run("ZeroMissing", func(t *testing.T) {
				dst := 42
				assertReadKey(t, map[string]any{}, "foo", &dst, keyOptional|zeroMissing)
				assert.Zero(t, dst, "should zero value when key is missing")
			})
		})
	})
}

type kiotaHeaderBuilder struct {
	rh abstractions.ResponseHeaders
}

func (k *kiotaHeaderBuilder) Build() *abstractions.ResponseHeaders {
	cp := new(abstractions.ResponseHeaders)
	cp.AddAll(&k.rh)
	return cp
}

func (k *kiotaHeaderBuilder) Clear() *kiotaHeaderBuilder {
	k.rh = abstractions.ResponseHeaders{}
	return k
}

func (k *kiotaHeaderBuilder) Without(key string) *kiotaHeaderBuilder {
	k.rh.Remove(key)
	return k
}

func (k *kiotaHeaderBuilder) With(key, value string, moreValues ...string) *kiotaHeaderBuilder {
	k.rh.Add(key, value, moreValues...)
	return k
}

func assertReadKey[T comparable](t *testing.T, src map[string]any, key string, dst *T, opts uint) (ok bool) {
	var checkZeroReason string
	var wellTyped bool

	required := opts&keyOptional == 0
	raw, present := src[key]

	if !present {
		wellTyped = true // don't check that a type error occurred
	} else {
		_, wellTyped = src[key].(T)
	}

	ok = true
	err := readKeyTo(src, key, dst, opts)

	if dst == nil { // short circuit: immediately stop testing
		return assert.ErrorIs(
			t, err, ErrNil,
			"should always return error identifying as ErrNil when %T is nil",
			dst,
		)
	} else if !present && !required {
		ok = assert.NoError(
			t, err,
			"not required: keyOptional is set",
		)

		if opts&zeroMissing != 0 {
			checkZeroReason = "key not present and zeroOnMissing flag set"
		}
	} else if !present && required {
		ok = assert.ErrorIs(
			t, err, ErrNotFound,
			"should indicate key %q was not found in map",
			key,
		)

		if opts&zeroOnError != 0 {
			checkZeroReason = "zeroOnError flag set and ErrNotFound occurred"
		}
	} else if present && !wellTyped {
		ok = assert.ErrorContains(
			t, err, "expected type",
			"error should describe a type mismatch\n"+
				"\tdst type: %T\n"+
				"\tmap type: %T\n",
			dst, raw,
		)

		if opts&zeroOnError != 0 {
			checkZeroReason = "zeroOnError flag set and type mismatch occurred"
		}
	} else {
		ok = assert.Equal(t, src[key].(T), *dst)
	}

	if ok && checkZeroReason != "" {
		ok = assert.Zero(t, *dst, checkZeroReason)
	}

	return ok
}

func TestUnexported(t *testing.T) {
	t.Run("kiotaNeverRetry", func(t *testing.T) {
		assert.False(t, kiotaNeverRetry(0, 0, nil, nil))
	})

	t.Run("alwaysExcludeLog", func(t *testing.T) {
		assert.True(t, alwaysExcludeLog(0, ""))
	})
}
