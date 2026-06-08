package azuresecrets

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestHTTPCodedErrorEx(t *testing.T) {
	t.Run("ErrorOnly", func(t *testing.T) {
		err := newCodedErrorEx(500, errTargetRootCredential)
		assert.Equal(t, 500, err.Code())
		assert.Equal(t, errTargetRootCredential.Error(), err.Error())
		assert.ErrorIs(t, err, errTargetRootCredential)
	})

	t.Run("StringOnly", func(t *testing.T) {
		err := newCodedErrorEx(403, "forbidden")
		assert.Equal(t, 403, err.Code())
		assert.Equal(t, "forbidden", err.Error())
	})

	t.Run("StringFormat", func(t *testing.T) {
		err := newCodedErrorEx(404, "foo: %w", errTargetRootCredential)
		assert.Equal(t, 404, err.Code())
		assert.Equal(t, fmt.Sprintf("foo: %s", errTargetRootCredential.Error()), err.Error())
		assert.ErrorIs(t, err, errTargetRootCredential)
	})

	t.Run("BadType", func(t *testing.T) {
		expect := fmt.Sprintf("cannot encode %T as coded error", true)
		assert.PanicsWithError(t, expect, func() { newCodedErrorEx(500, true) })
	})
}

func TestAsCodedErrorEx(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		assert.NoError(t, asCodedErrorEx(nil))
	})

	t.Run("IsAlreadyCodedErrorEx", func(t *testing.T) {
		err := newCodedErrorEx(500, "simple")
		assert.Same(t, err, asCodedErrorEx(err))
	})

	t.Run("logical.HTTPCodedError", func(t *testing.T) {
		base := logical.CodedError(402, "pay up, fool")
		err := asCodedErrorEx(base)
		assert.Equal(t, 402, err.(httpCodedErrorEx).Code())
		assert.Same(t, base, errors.Unwrap(err))
	})

	t.Run("errTargetRootCredential", func(t *testing.T) {
		err := asCodedErrorEx(fmt.Errorf("%w abcd", errTargetRootCredential))
		assert.ErrorIs(t, err, errTargetRootCredential)
		assert.Equal(t, 403, err.(httpCodedErrorEx).Code())
	})
}
