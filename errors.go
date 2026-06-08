package azuresecrets

import (
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

var _ httpCodedErrorEx = (*codedErrorEx)(nil)

// httpCodedErrorEx is an extended version of [logical.HTTPCodedError] that
// supports error unwrapping.
type httpCodedErrorEx interface {
	logical.HTTPCodedError
	Unwrap() error
}

type codedErrorEx struct {
	code int
	err  error
}

// asCodedErrorEx uses an error's identity to opportunistically convert it to
// an [httpCodedErrorEx]. It does nothing if the error is nil, or returns the
// original error if no conversion is performed.
func asCodedErrorEx(err error) error {
	if err == nil {
		return nil
	} else if _, ok := (err).(httpCodedErrorEx); ok {
		return err
	} else if logErr, ok := (err).(logical.HTTPCodedError); ok {
		err = newCodedErrorEx(logErr.Code(), logErr) // preserve for unwrapping
	} else if errors.Is(err, errTargetRootCredential) {
		err = newCodedErrorEx(403, err)
	}

	return err
}

// newCodedErrorEx is similar to [logical.CodedError], but it accepts either
//
//   - a string: will be converted to an error via either [errors.New] (if no
//     additional arguments are present), or via [fmt.Errorf].
//   - an error: will be wrapped. If additional arguments were provided, they
//     are **ignored**.
//
// The msgOrError MUST be a string or error, otherwise a panic occurs.
func newCodedErrorEx(code int, msgOrError any, args ...any) httpCodedErrorEx {
	var ce codedErrorEx
	ce.code = code
	switch t := msgOrError.(type) {
	case string:
		if len(args) > 0 {
			ce.err = fmt.Errorf(t, args...)
		} else {
			ce.err = errors.New(t)
		}
	case error:
		ce.err = t
	default:
		panic(fmt.Errorf("cannot encode %T as coded error", t))
	}

	return &ce
}

func (ce *codedErrorEx) Code() int     { return ce.code }
func (ce *codedErrorEx) Error() string { return ce.err.Error() }
func (ce *codedErrorEx) Unwrap() error { return ce.err }
