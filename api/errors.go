package api

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

const (
	CodeDirectoryConcurrency = ErrorCode("Directory_ConcurrencyViolation")

	msgAppNotFound = "no application found"
)

// errAppNotFound is a simple error identifying as [logical.ErrNotFound]
// that always returns [msgAppNotFound]:
//
//	"no application found"
var ErrAppNotFound *appNotFoundError

// ============================================================================
// |                               [ErrorCode]                                |
// ============================================================================

// ErrorCode is a case-insensitive machine-readable [error] string used to
// describe a static error condition.
type ErrorCode string

// GetErrorCode extracts the error code from the given source error, returning
// the zero value of [ErrorCode] if not possible (see: [ErrorCode.IsValid]).
func GetErrorCode(src error) (ec ErrorCode) {
	switch t := src.(type) {
	case ErrorCode:
		ec = t
	case *Error:
		if t != nil {
			ec = t.Code
		}
	case odataCodeGetter:
		if t != nil {
			ec = ErrorCode(Deref(t.GetCode()))
		}
	case odataEscapedErrorGetter:
		if t == nil {
			break
		} else if me := t.GetErrorEscaped(); me != nil {
			ec = ErrorCode(Deref(me.GetCode()))
		}
	}

	return ec
}

// Equal indicates if this [ErrorCode] and the other are equivalent by using
// case-insensitive string matching.
func (ec ErrorCode) Equal(other string) bool {
	return strings.EqualFold(string(ec), other)
}

// Error returns the receiver as a string and implements [error].
func (ec ErrorCode) Error() string { return string(ec) }

// IsValid indicates if this [ErrorCode] is an actionable error (true) or
// should be ignored (false). The zero value of [ErrorCode] is always invalid.
func (ec ErrorCode) IsValid() bool { return ec != "" }

// OrNil returns the receiver as a non-nil [error] if [ErrorCode.IsValid] would
// return true, otherwise it returns a nil [error].
func (ec ErrorCode) OrNil() error {
	if ec.IsValid() {
		return ec
	}

	return nil
}

// String returns the receiver as a string and implements [fmt.Stringer].
func (ec ErrorCode) String() string { return string(ec) }

// Is indicates if this [ErrorCode] and the given [error] are equivalent. If
// the target is an [Error] or an error from the "odataerrors" package, it
// checks against the error code stored on the error.
func (ec ErrorCode) Is(target error) bool {
	return ec.Equal(GetErrorCode(target).String())
}

// ============================================================================
// |                                  [Error]                                 |
// ============================================================================

// Error represents the error type returned by the Microsoft Graph API
// service. For more information, refer to [Microsoft Graph API Documentation]
// and/or [Microsoft REST API Error Response Guidelines].
//
// [Microsoft Graph API Documentation]: https://learn.microsoft.com/en-us/graph/errors
// [Microsoft REST API Error Response Guidelines]: https://github.com/microsoft/api-guidelines/blob/vNext/graph/articles/errorResponses.md
type Error struct {
	// Code is a short, machine-readable server-defined error code describing
	// the error that occurred (e.g. "Directory_ConcurrencyViolation"). This
	// value is
	//
	//	- *SAFE* to use as a dependency for error handling
	//	- always present on the top-level error when the Graph API endpoint
	//    responds with an error.
	Code ErrorCode `json:"code,omitempty"`

	// Message is a developer ready message about the error that occurred. This
	// value is
	//
	//	- *NOT SAFE* to use as a dependency for error handling (use the
	//	  [Error.Code] field, instead).
	//	- always present on the top-level error when the Graph API endpoint
	//    responds with an error.
	Message string `json:"message,omitempty"`

	// Target of the error. Not always present.
	Target string `json:"target,omitempty"`

	// Details contains specific errors that led to this reported error.
	Details []Error `json:"details,omitempty"`

	// InnerError contains more specific information about the error.
	//
	// NOTE(bueschels): Microsoft's documentation refers to this field as an
	// "[Error] object," but this is not actually the case.
	//
	// Instead, the msgraph-sdk-go package returns an interface which does not
	// implement or inherit the actual [error] interface. For this reason, we
	// use [ErrorMetadata], since this seems to align better with the actual
	// use of this field within the official Graph SDK.
	InnerError *InnerErrorData `json:"innerError,omitempty"`

	// ResponseInfo provides additional HTTP details sent along with the
	// error when set.
	ResponseInfo *ErrorResponseInfo `json:"responseInfo,omitempty"`

	// AdditionalData contains additional data for the error that doesn't
	// belong to a specific struct field.
	AdditionalData map[string]any `json:"additionalData,omitempty"`

	orig *odataerrors.ODataError
}

// ConvertToError is a best-effort constructor which converts the given [error]
// into an [Error] and indicates if the conversion was successful. It succeeds
// when the source error is
//
//   - an [Error] whose [Error.IsValid] method would return true. In this case,
//     the [Error] instance backing the source is returned as-is (no copying).
//   - a pointer to an [odataerrors.ODataError] instance with a valid escaped
//     error set, such that an [ErrorCode] can be determined. Afterwards, the
//     [Error.Unwrap] method returns the original error.
//
// In the second case, the equivalent of the following call is used to
// determine the [ErrorCode] required for the conversion:
//
//	code := *src.(*odataerrors.ODataError).GetErrorEscaped().GetCode()
func ConvertToError(src error) (*Error, bool) {
	switch t := src.(type) {
	case *Error:
		if t.IsValid() {
			return t, true
		}
	case *odataerrors.ODataError:
		var e Error
		if e.init(t) {
			return &e, true
		}
	}

	return nil, false
}

// TryConvertToError is a convenience function for opportunistically converting
// a source error to an [Error] (via [ConvertToError]). If conversion fails or
// is not possible, the original argument is returned.
func TryConvertToError(src error) error {
	if e, ok := ConvertToError(src); ok {
		return e
	}

	return src
}

// Error implements [error] by returning the [Error.Message] value. It returns
// an empty string if [Error.IsValid] would return false.
func (e *Error) Error() (s string) {
	if e.IsValid() {
		s = e.Message
	}

	return s
}

// Is indicates if the [Error.Code] stored within this [Error] matches
// the error code value of the given target. The target must be one of
// the following types:
//
//   - [Error]
//   - [ErrorCode]
//   - [odataCodeGetter]
//   - [odataEscapedErrorGetter]
//
// Note: when the target is another [Error], both the receiver and target
// must point to the same address. Otherwise, the result is always false.
func (e *Error) Is(target error) (ok bool) {
	switch t := target.(type) {
	case *Error:
		ok = e == t
	default:
		ok = e.IsValid() && e.Code.Equal(GetErrorCode(target).String())
	}

	return ok
}

// OrNil returns the receiver as a non-nil [error] if [Error.IsValid] would
// return true, otherwise it returns a nil [error].
func (e *Error) OrNil() error {
	if e.IsValid() {
		return e
	}

	return nil
}

// IntoLogger places fields from this [Error] into the given [hclog.Logger].
// It does nothing if either the [hclog.Logger] or this [Error] are nil.
//
// The table below summarizes the fields placed into the returned logger:
//
//	| Logger Key (no pfx) | Struct Field                     |
//	| ------------------- | -------------------------------- |
//	| `code`              | Error.Code                       |
//	| `status_code`       | Error.ResponseInfo.StatusCode    |
//	| `target`            | Error.Target                     |
//	| `client_request_id` | Error.InnerError.ClientRequestID |
//	| `request_id`        | Error.InnerError.RequestID       |
//	| `type`              | Error.InnerError.Type            |
//
// An optional string may be given to prefix to all logged keys.
func (e *Error) IntoLogger(logger hclog.Logger, prefix ...string) hclog.Logger {
	var pairs []any

	if logger == nil || e == nil {
		return logger
	}

	pfx := cmp.Or(prefix...)

	if e.Code != "" {
		pairs = append(pairs, fmt.Sprintf("%scode", pfx), e.Code)
	}

	if e.Target != "" {
		pairs = append(pairs, fmt.Sprintf("%starget", pfx), e.Target)
	}

	if ri := e.ResponseInfo; ri != nil {
		if ri.StatusCode != 0 {
			pairs = append(pairs, fmt.Sprintf("%sstatus_code", pfx), ri.StatusCode)
		}
	}

	if ie := e.InnerError; ie != nil {
		if ie.ClientRequestID != "" {
			pairs = append(pairs, fmt.Sprintf("%sclient_request_id", pfx), ie.ClientRequestID)
		}

		if ie.RequestID != "" {
			pairs = append(pairs, fmt.Sprintf("%srequest_id", pfx), ie.RequestID)
		}

		if ie.Type != "" {
			pairs = append(pairs, fmt.Sprintf("%stype", pfx), ie.Type)
		}
	}

	if len(pairs) > 0 {
		logger = logger.With(pairs...)
	}

	return logger
}

func (e *Error) IsValid() bool {
	return e != nil && e.Code.IsValid()
}

// Unwrap returns the original [error] from which this [Error] was initialized,
// otherwise nil. If a non-nil error is returned, it will be a pointer to an
// [odataerrors.ODataError] object.
func (e *Error) Unwrap() error {
	if e != nil && e.orig != nil {
		return e.orig
	}

	return nil
}

// init initializes the [Error] from the top-level (root) error
// returned from an API response.
func (e *Error) init(src *odataerrors.ODataError) bool {
	if src == nil {
		return false
	} else if me := src.GetErrorEscaped(); me == nil {
		return false
	} else if e.Code = ErrorCode(Deref(me.GetCode())); e.Code.IsValid() {
		e.Message = Deref(me.GetMessage())
		e.Target = Deref(me.GetTarget())
		e.AdditionalData = CopyAdditionalData(me)
		e.initInnerError(me.GetInnerError())
		e.initResponseInfo(src)

		details := me.GetDetails()
		e.Details = make([]Error, 0, len(details))
		for i := range details {
			e.Details = append(e.Details, Error{
				Code:           ErrorCode(Deref(details[i].GetCode())),
				Message:        Deref(details[i].GetMessage()),
				Target:         Deref(details[i].GetTarget()),
				AdditionalData: CopyAdditionalData(details[i]),
			})
		}

		e.orig = src // save original error for unwrapping
		return true
	}

	return false
}

func (e *Error) initResponseInfo(src *odataerrors.ODataError) bool {
	var eri ErrorResponseInfo
	e.ResponseInfo = nil

	if eri.StatusCode = src.GetStatusCode(); eri.StatusCode > 0 && eri.StatusCode < 600 {
		var whence []time.Time

		if ie := e.InnerError; ie != nil && ie.Date != nil && !ie.Date.IsZero() {
			whence = append(whence, *ie.Date)
		}

		eri.Headers = CopyHeaders(src.ResponseHeaders)
		eri.RetryAfter = TryParseRetryAfter(eri.Headers, whence...)
		e.ResponseInfo = &eri
	}

	return e.ResponseInfo != nil
}

func (e *Error) initInnerError(src odataerrors.InnerErrorable) bool {
	if e.InnerError = nil; src != nil {
		e.InnerError = &InnerErrorData{
			ClientRequestID: Deref(src.GetClientRequestId()),
			RequestID:       Deref(src.GetRequestId()),
			Date:            src.GetDate(),
			Type:            Deref(src.GetOdataType()),
			AdditionalData:  maps.Clone(src.GetAdditionalData()),
		}
	}

	return e.InnerError != nil
}

// ============================================================================
// |                             [InnerErrorData]                             |
// ============================================================================

// InnerErrorData is additional data associated with the root of an [Error].
type InnerErrorData struct {
	// ClientRequestID is the UUID generated by the Graph API client when it
	// performs an API call.
	ClientRequestID string `json:"clientRequestId,omitempty"`

	// RequestID is a UUID internal to the Graph API service.
	//
	// NOTE(bueschels): It is unclear from documentation what this ID actually
	// is.
	RequestID string `json:"requestId,omitempty"`

	// Date is the time when the error occurred.
	Date *time.Time `json:"date,omitempty"`

	// Type is the @odata.type property value of the error.
	Type string `json:"type,omitempty"`

	// AdditionalData contains additional data for the error that doesn't
	// belong to a specific struct field.
	AdditionalData map[string]any `json:"additionalData,omitempty"`
}

// ============================================================================
// |                            [ErrorResponseInfo]                           |
// ============================================================================

// ErrorResponseInfo contains additional response information associated with
// an [Error].
type ErrorResponseInfo struct {
	// StatusCode is the HTTP response code returned alongside the [Error].
	StatusCode int `json:"statusCode,omitempty"`

	// Headers present in the HTTP response for the associated [Error].
	Headers http.Header `json:"headers,omitempty"`

	// RetryAfter is non-zero if the "Retry-After" header was set in the API
	// error response, as a result of exceeding throttling limits.
	RetryAfter *time.Time `json:"retryAfter,omitempty"`
}

// ============================================================================
// |                            [appNotFoundError]                            |
// ============================================================================

// appNotFoundError is a compatability error which also identifies as
// [logical.ErrNotFound]. The original error that this type replaces
// was a naive error incapable of wrapping [logical.ErrNotFound] using
// simple "%w" directives.
//
// The nil receiver is always valid, never panics, and is the recommended
// error value to use.
type appNotFoundError struct{}

func (*appNotFoundError) Error() string { return msgAppNotFound }

func (*appNotFoundError) Is(target error) (ok bool) {
	if _, ok = target.(*appNotFoundError); !ok {
		ok = target != nil && errors.Is(target, logical.ErrNotFound)
	}

	return ok
}

// ============================================================================
// |                     Unexported / uninteresting stuff                     |
// ============================================================================

// odataCodeGetter is an _extremely_ simplified subset of the
// [odataerrors.ODataErrorable] interface, which is implemented
// by the [odataerrors.ODataError] pointer receiver.
//
// Greatly simplifies unit testing.
type odataEscapedErrorGetter interface {
	GetErrorEscaped() odataerrors.MainErrorable
}

// odataCodeGetter is an _extremely_ simplified subset of the
// [odataerrors.MainErrorable] interface.
//
// Greatly simplifies unit testing.
type odataCodeGetter interface {
	GetCode() *string
}
