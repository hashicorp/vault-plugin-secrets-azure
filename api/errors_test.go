package api

import (
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
)

// FakeCodeGetter implements the [odataCodeGetter] interface for test purposes.
type FakeCodeGetter struct {
	v *string
}

// FakeLogger implements the [hclog.Logger] interface in order to test
type FakeLogger struct {
	Pairs map[string]any
}

// ============================================================================
// |                             [FakeCodeGetter]                             |
// ============================================================================

func NewFakeCodeGetter(code ...string) *FakeCodeGetter {
	var f FakeCodeGetter
	return f.With(code...)
}

func (f FakeCodeGetter) Error() string    { return Deref(f.v) }
func (f FakeCodeGetter) GetCode() *string { return f.v }

func (f *FakeCodeGetter) With(s ...string) *FakeCodeGetter {
	if len(s) == 0 {
		f.v = nil
	} else if f.v == nil {
		f.v = new(s[0])
	} else {
		*f.v = s[0]
	}

	return f
}

// ============================================================================
// |                               [FakeLogger]                               |
// ============================================================================

func NewFakeLogger() *FakeLogger {
	return &FakeLogger{Pairs: map[string]any{}}
}

func (f *FakeLogger) Log(_ hclog.Level, _ string, _ ...any)                     {}
func (f *FakeLogger) Trace(_ string, _ ...any)                                  {}
func (f *FakeLogger) Debug(_ string, _ ...any)                                  {}
func (f *FakeLogger) Info(_ string, _ ...any)                                   {}
func (f *FakeLogger) Warn(_ string, _ ...any)                                   {}
func (f *FakeLogger) Error(_ string, _ ...any)                                  {}
func (f *FakeLogger) SetLevel(_ hclog.Level)                                    {}
func (f *FakeLogger) IsTrace() bool                                             { return false }
func (f *FakeLogger) IsDebug() bool                                             { return false }
func (f *FakeLogger) IsInfo() bool                                              { return false }
func (f *FakeLogger) IsWarn() bool                                              { return false }
func (f *FakeLogger) IsError() bool                                             { return false }
func (f *FakeLogger) ImpliedArgs() []any                                        { return nil }
func (f *FakeLogger) GetLevel() hclog.Level                                     { return 0 }
func (f *FakeLogger) Name() string                                              { return "" }
func (f *FakeLogger) Named(_ string) hclog.Logger                               { return f }
func (f *FakeLogger) ResetNamed(_ string) hclog.Logger                          { return f }
func (f *FakeLogger) StandardLogger(_ *hclog.StandardLoggerOptions) *log.Logger { return nil }
func (f *FakeLogger) StandardWriter(_ *hclog.StandardLoggerOptions) io.Writer   { return nil }

func (f *FakeLogger) With(pairs ...any) hclog.Logger {
	var out FakeLogger

	out.Pairs = maps.Clone(f.Pairs)
	maps.Copy(out.Pairs, PairsToMap(pairs...))

	return &out
}

func PairsToMap(pairs ...any) map[string]any {
	var n int
	if n = len(pairs); n&1 == 1 {
		panic(fmt.Errorf("expected an even number of args (got %d)", n))
	}

	m := make(map[string]any, n>>1)

	for i := 0; i < n; i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			panic(fmt.Errorf("at index %d: expected key as %T, have %T", i, key, pairs[i]))
		}

		m[key] = pairs[i+1]
	}

	return m
}

// ============================================================================
// |                                [ErrorCode]                               |
// ============================================================================

func TestErrorCode(t *testing.T) {
	t.Run("IsValid", func(t *testing.T) {
		t.Run("Zero", func(t *testing.T) {
			var invalid ErrorCode
			assert.False(t, invalid.IsValid())
		})

		t.Run("Valid", func(t *testing.T) {
			assert.True(t, ErrorCode("notAnEmptyString").IsValid())
		})
	})

	t.Run("Equal", func(t *testing.T) {
		for _, tc := range []struct {
			Name   string
			Code   ErrorCode
			Other  string
			Expect bool
		}{
			{
				Name:   "EmptyCode_EmptyString",
				Code:   "",
				Other:  "",
				Expect: true,
			},
			{
				Name:   "ValidCode_EmptyString",
				Code:   "fooBarBaz",
				Other:  "",
				Expect: false,
			},
			{
				Name:   "ValidCode_EmptyString",
				Code:   "fooBarBaz",
				Other:  "",
				Expect: false,
			},
			{
				Name:   "Equal_CaseMatches",
				Code:   "fooBarBaz",
				Other:  "fooBarBaz",
				Expect: true,
			},
			{
				Name:   "Equal_CaseDiffers",
				Code:   "fooBarBaz",
				Other:  "FoObArbAZ",
				Expect: true,
			},
		} {
			t.Run(tc.Name, func(t *testing.T) {
				assertion := assert.True
				should := "should"

				if !tc.Expect {
					assertion = assert.False
					should += " not"
				}

				assertion(
					t, tc.Code.Equal(tc.Other),
					"Values %s be considered equal:\n"+
						"\tReceiver: %T(%q)\n"+
						"\tOther   : %q\n",
					should, tc.Code, string(tc.Code), tc.Other,
				)
			})
		}
	})

	t.Run("Error", func(t *testing.T) {
		assert.Equal(t, ErrorCode("fooBarBaz").Error(), "fooBarBaz")
	})

	t.Run("String", func(t *testing.T) {
		assert.Equal(t, ErrorCode("fooBarBaz").String(), "fooBarBaz")
	})

	t.Run("Is", func(t *testing.T) {
		const zero ErrorCode = ""

		for _, tc := range []struct {
			Name   string
			Desc   string
			Code   ErrorCode
			Target error
			Expect bool
		}{
			{
				Name: "ErrorCode_NotEqual",
				Desc: fmt.Sprintf(
					"%T values represent distinct states and are only equal "+
						"if their content matches (case-insensitive)",
					zero,
				),
				Code:   "fooBarBaz",
				Target: ErrorCode("qux"),
				Expect: false,
			},
			{
				Name:   "ErrorCode_EqualCaseDiffers",
				Code:   "fooBarBaz",
				Target: ErrorCode("FoObArbAZ"), // case-insensitive
				Expect: true,
			},
			{
				Name:   "ErrorCode_EqualCaseMatches",
				Code:   "fooBarBaz",
				Target: ErrorCode("fooBarBaz"),
				Expect: true,
			},
			{
				Name: "EmptyErrorCode_GetCodeNilMatches",
				Desc: "Nil *string pointer returned by GetCode() should be " +
					"treated as an empty string during comparisons.",
				Code:   "",
				Target: NewFakeCodeGetter(), // GetCode() returns nil
				Expect: true,
			},
			{
				Name:   "GetCodeEquivalent",
				Code:   "fooBarBaz",
				Target: NewFakeCodeGetter("FoObArbAZ"), // case-insensitive
				Expect: true,
			},
			{
				Name: "PkgError_Nil", // as in [Error]
				Desc: fmt.Sprintf(
					"Nil %T is not equivalent to a nil error",
					(*Error)(nil),
				),
				Code:   "fooBarBaz",
				Target: (*Error)(nil),
				Expect: false,
			},
			{
				Name:   "PkgError_CodeNotEqual",
				Code:   "fooBarBaz",
				Target: &Error{Code: "qux"},
				Expect: false,
			},
			{
				Name:   "PkgError_CodeEqual",
				Code:   "fooBarBaz",
				Target: &Error{Code: "fooBarBaz"},
				Expect: true,
			},
			{
				Name:   "Default",
				Desc:   "Should never identify as unhandled error types.",
				Code:   "fooBarBaz",
				Target: errors.New("never matches"),
				Expect: false,
			},
			// TODO: test [odataEscapedErrorGetter]
		} {
			t.Run(tc.Name, func(t *testing.T) {
				var msgAndArgs []any
				if tc.Desc != "" {
					msgAndArgs = []any{tc.Desc}
				}

				assert.Equal(t, tc.Expect, tc.Code.Is(tc.Target), msgAndArgs...)
				if tc.Expect {
					assert.ErrorIs(t, tc.Code, tc.Target)
				} else {
					assert.NotErrorIs(t, tc.Code, tc.Target)
				}
			})
		}
	})

	t.Run("OrNil", func(t *testing.T) {
		t.Run("Zero", func(t *testing.T) {
			var ec ErrorCode

			assert.NoError(
				t, ec.OrNil(),
				"zero value of %T should not produce an error",
				ec,
			)
		})

		t.Run("Valid", func(t *testing.T) {
			ec := ErrorCode("fooBarBaz")

			assert.Error(
				t, ec.OrNil(),
				"non-empty %T value should produce an error",
				ec,
			)
		})
	})
}

// ============================================================================
// |                                 [Error]                                  |
// ============================================================================

func TestError(t *testing.T) {
	t.Run("Convert", func(t *testing.T) {
		t.Run("Invalid", func(t *testing.T) {
			for _, tc := range []struct {
				Name   string
				Source error
			}{
				{Name: "Interface", Source: nil},
				{Name: "NilError", Source: (*Error)(nil)},
				{Name: "NilOdataError", Source: (*odataerrors.ODataError)(nil)},
				{Name: "ZeroError", Source: &Error{}},
			} {
				t.Run(tc.Name, func(t *testing.T) {
					e, ok := ConvertToError(tc.Source)
					assert.Nil(t, e)
					assert.False(t, ok)
				})
			}
		})

		t.Run("Error", func(t *testing.T) {
			orig := &Error{Code: "fooBarBaz", Target: "t1"}
			e, ok := ConvertToError(orig)
			assert.Same(t, orig, e)
			assert.True(t, ok)
		})

		t.Run("ODataError", func(t *testing.T) {
			const timeFmt = "2006-01-02T15:04:05.000Z07:00"
			start := time.Now().Truncate(time.Millisecond)
			inner := odataerrors.NewInnerError()
			inner.SetDate(&start)
			inner.SetClientRequestId(new("client-req-id"))
			inner.SetRequestId(new("req-id"))
			inner.SetOdataType(new("object"))

			details := []odataerrors.ErrorDetailsable{}

			for i := range 3 {
				detail := odataerrors.NewErrorDetails()
				detail.SetCode(new(fmt.Sprintf("code-%d", i)))
				detail.SetMessage(new(fmt.Sprintf("message-%d", i)))
				detail.SetTarget(new(fmt.Sprintf("target-%d", i)))

				details = append(details, detail)
			}

			esc := odataerrors.NewMainError()
			esc.SetCode(new("fooBarBaz"))
			esc.SetMessage(new("message"))
			esc.SetTarget(new("target"))
			esc.SetInnerError(inner)
			esc.SetDetails(details)

			ode := odataerrors.NewODataError()
			ode.SetErrorEscaped(esc)
			ode.SetStatusCode(400)
			ode.GetResponseHeaders().Add("retry-after", "120")

			e, ok := ConvertToError(ode)

			if !assert.NotNil(t, e) && !assert.True(t, ok) {
				return
			}

			assert.Equal(t, ErrorCode("fooBarBaz"), e.Code, "Field: Code")
			assert.Equal(t, "message", e.Message, "Field: Message")
			assert.Equal(t, "target", e.Target, "Field: Target")

			prefix := "Field: Details"
			if assert.Len(t, e.Details, 3, prefix) {
				for i := range e.Details {
					detail := &e.Details[i]

					assert.Equal(
						t, ErrorCode(fmt.Sprintf("code-%d", i)), detail.Code,
						"%s[%d].Code", prefix, i,
					)

					assert.Equal(
						t, fmt.Sprintf("message-%d", i), detail.Message,
						"%s[%d].Message", prefix, i,
					)

					assert.Equal(
						t, fmt.Sprintf("target-%d", i), detail.Target,
						"%s[%d].Target", prefix, i,
					)
				}
			}

			prefix = "Field: InnerError"
			if ie := e.InnerError; assert.NotNil(t, ie, prefix) {
				if date := ie.Date; assert.NotNil(t, date, "%s.Date", prefix) {
					assert.True(
						t, date.Equal(start),
						"%s.Date\n\tExpect: %s\n\tActual: %s\n",
						prefix, start.Format(timeFmt), date.Format(timeFmt),
					)
				}

				assert.Equal(
					t, "client-req-id", ie.ClientRequestID,
					"%s.ClientRequestID", prefix,
				)
				assert.Equal(t, "req-id", ie.RequestID, "%s.RequestID", prefix)
				assert.Equal(t, "object", ie.Type, "%s.Type", prefix)
			}

			prefix = "Field: ResponseInfo"
			if ri := e.ResponseInfo; assert.NotNil(t, ri, prefix) {
				assert.Equal(t, 400, ri.StatusCode, "%s.StatusCode", prefix)
				if assert.NotNil(t, ri.RetryAfter, "%s.RetryAfter", prefix) {
					expect := start.Add(time.Duration(120) * time.Second)
					assert.True(
						t, ri.RetryAfter.Equal(expect),
						"%s.Date\n\tExpect: %s\n\tActual: %s\n",
						prefix, expect.Format(timeFmt), ri.RetryAfter.Format(timeFmt),
					)
				}
			}

			raw := e.Unwrap()
			unwrapped, ok := raw.(*odataerrors.ODataError)
			if assert.True(t, ok, "casting Unwrap() to %T", unwrapped) {
				assert.Same(t, ode, unwrapped, "Unwrapped error")
			}
		})
	})

	t.Run("Error", func(t *testing.T) {
		t.Run("Nil", func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Empty(t, (*Error)(nil).Error())
			})
		})

		t.Run("Invalid", func(t *testing.T) {
			var e Error
			e.Message = "not valid because Code is empty"
			assert.Empty(t, e.Error(), e.Message)
		})

		t.Run("Valid", func(t *testing.T) {
			var e Error
			e.Code = "fooBarBaz"
			e.Message = "qux"
			assert.Equal(t, "qux", e.Error())
		})
	})

	t.Run("Is", func(t *testing.T) {
		errObj := &Error{Code: "fooBarBaz", Target: "t1"}
		errObjDupe := &Error{Code: "fooBarBaz", Target: "t1"}

		for _, tc := range []struct {
			Name   string
			Desc   string
			Error  *Error
			Target error
			Expect bool
		}{
			{
				Name:   "ErrorCode_NotEqual",
				Error:  errObj,
				Target: ErrorCode("qux"),
				Expect: false,
			},
			{
				Name:   "ErrorCode_EqualCaseDiffers",
				Error:  errObj,
				Target: ErrorCode("FoObArbAZ"), // case-insensitive
				Expect: true,
			},
			{
				Name:   "ErrorCode_EqualCaseMatches",
				Error:  errObj,
				Target: errObj.Code,
				Expect: true,
			},
			{
				Name: "EmptyErrorCode_GetCodeNil_NoMatch",
				Desc: "Nil *string pointer returned by GetCode() should be " +
					"considered invalid and never identifies as another error.",
				Error:  &Error{},
				Target: NewFakeCodeGetter(), // GetCode() returns nil
				Expect: false,
			},
			{
				Name:   "GetCodeEquivalent",
				Error:  errObj,
				Target: NewFakeCodeGetter("FoObArbAZ"), // case-insensitive
				Expect: true,
			},
			{
				Name:   "ErrorCode_NoMatch",
				Error:  errObj,
				Target: ErrorCode("qux"),
				Expect: false,
			},
			{
				Name:   "Match_Self",
				Error:  errObj,
				Target: errObj,
				Expect: true,
			},
			{
				Name:   "NoMatch_Other",
				Error:  errObj,
				Target: errObjDupe,
				Expect: false,
			},
			{
				Name:   "Default",
				Desc:   "Should never identify as unhandled error types.",
				Error:  errObj,
				Target: errors.New("fooBarBaz"),
				Expect: false,
			},
			// TODO: test [odataEscapedErrorGetter]
		} {
			t.Run(tc.Name, func(t *testing.T) {
				var msgAndArgs []any
				if tc.Desc != "" {
					msgAndArgs = []any{tc.Desc}
				}

				assert.Equal(t, tc.Expect, tc.Error.Is(tc.Target), msgAndArgs...)
				if tc.Expect {
					assert.ErrorIs(t, tc.Error, tc.Target)
				} else {
					assert.NotErrorIs(t, tc.Error, tc.Target)
				}
			})
		}
	})

	t.Run("IntoLogger", func(t *testing.T) {
		t.Run("Nil", func(t *testing.T) {
			t.Run("Error", func(t *testing.T) {
				var e *Error
				var logger hclog.Logger = NewFakeLogger()

				assert.NotPanics(t, func() {
					assert.Same(t, logger, e.IntoLogger(logger))
				})
			})

			t.Run("Logger", func(t *testing.T) {
				var e Error
				var logger hclog.Logger

				assert.NotPanics(t, func() {
					assert.Nil(t, e.IntoLogger(logger))
				})
			})
		})

		t.Run("Zero", func(t *testing.T) {
			t.Run("Error", func(t *testing.T) {
				var e Error
				logger := NewFakeLogger()
				logger.Pairs["a"] = 0
				expectLen := len(logger.Pairs)
				result := e.IntoLogger(logger)

				assert.Len(
					t, result.(*FakeLogger).Pairs, expectLen,
					"should not have placed any data into logger pairs",
				)
			})
		})

		t.Run("All", func(t *testing.T) {
			e := &Error{
				Code:   "fooBarBaz",
				Target: "t1",
				ResponseInfo: &ErrorResponseInfo{
					StatusCode: 400,
				},
				InnerError: &InnerErrorData{
					ClientRequestID: "client-id",
					RequestID:       "req-id",
					Type:            "object",
				},
			}

			expectPairs := map[string]any{
				"code":              e.Code,
				"target":            e.Target,
				"status_code":       e.ResponseInfo.StatusCode,
				"client_request_id": e.InnerError.ClientRequestID,
				"request_id":        e.InnerError.RequestID,
				"type":              e.InnerError.Type,
			}

			logger := NewFakeLogger()
			result := e.IntoLogger(logger)
			assert.Equal(t, expectPairs, result.(*FakeLogger).Pairs)
		})
	})

	t.Run("OrNil", func(t *testing.T) {
		t.Run("Zero", func(t *testing.T) {
			var e Error

			assert.NoError(
				t, e.OrNil(),
				"zero value of %T should not produce an error",
				e,
			)
		})

		t.Run("Nil", func(t *testing.T) {
			var e *Error

			assert.NotPanics(t, func() {
				assert.NoError(
					t, (*Error)(nil).OrNil(),
					"nil %T should not produce an error",
					e,
				)
			})
		})

		t.Run("Valid", func(t *testing.T) {
			e := &Error{Code: "fooBarBaz"}

			assert.Error(
				t, e.OrNil(),
				"valid %T should produce an error",
				e,
			)
		})
	})
}

// ============================================================================
// |                            [appNotFoundError]                            |
// ============================================================================

func TestAppNotFoundError(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		var e *appNotFoundError
		assert.NotPanics(t, func() {
			assert.Equal(t, e.Error(), msgAppNotFound)
		})
	})

	t.Run("Is", func(t *testing.T) {
		t.Run("ErrAppNotFound", func(t *testing.T) {
			var e *appNotFoundError
			assert.ErrorIs(
				t, e, ErrAppNotFound,
				"should always identify as self",
			)
		})

		t.Run("logical.ErrNotFound", func(t *testing.T) {
			assert.ErrorIs(t, ErrAppNotFound, logical.ErrNotFound)
		})
	})
}
