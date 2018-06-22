package azuresecrets

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
)

func GetInternalString(req *logical.Request, name string) (data string, err error) {
	if dataRaw, ok := req.Secret.InternalData[name]; ok {
		if data, ok = dataRaw.(string); ok {
			return
		} else {
			return "", fmt.Errorf("internal data '%s' is invalid", name)
		}
	}
	return "", fmt.Errorf("internal data '%s' not found", name)
}
