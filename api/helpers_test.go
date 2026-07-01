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
