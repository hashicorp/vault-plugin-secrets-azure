package azuresecrets

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/go-test/deep"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/jsonutil"
)

func equal(tb testing.TB, exp, act interface{}) {
	tb.Helper()
	if diff := deep.Equal(exp, act); diff != nil {
		tb.Fatal(diff)
	}
}

// An helpful temporary alternative when looking for
// diffs in a complicated structure.
func equalJ(tb testing.TB, exp, act interface{}) {
	tb.Helper()
	if !reflect.DeepEqual(exp, act) {
		e, err := json.MarshalIndent(exp, "", "  ")
		if err != nil {
			tb.Fatal(err)
		}
		a, err := json.MarshalIndent(act, "", "  ")
		if err != nil {
			tb.Fatal(err)
		}
		tb.Fatalf("\nexpected:  %s\nactual:    %s", string(e), string(a))
	}
}

func ok(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("\nunexpected error: %s", err.Error())
	}
}

func encode(data interface{}) string {
	d, err := jsonutil.EncodeJSON(data)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(d))
}

func compactJSON(s string) string {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		panic(err)
	}
	return b.String()
}

func newUUID() string {
	u, _ := uuid.GenerateUUID()
	return u
}
