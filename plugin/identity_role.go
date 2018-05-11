package azuresecrets

import (
	"context"
	"fmt"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
)

type IdentityRole struct {
	Name       string
	Identities []string
}

//
func (rs *IdentityRole) validate() error {
	var err *multierror.Error
	//	if rs.Name == "" {
	//		err = multierror.Append(err, errors.New("role set name is empty"))
	//	}
	//
	//	if rs.SecretType == "" {
	//		err = multierror.Append(err, errors.New("role set secret type is empty"))
	//	}
	//
	//	if rs.AccountId == nil {
	//		err = multierror.Append(err, fmt.Errorf("role set should have account associated"))
	//	}
	//
	//	if len(rs.Bindings) == 0 {
	//		err = multierror.Append(err, fmt.Errorf("role set bindings cannot be empty"))
	//	}
	//
	//	if len(rs.RawBindings) == 0 {
	//		err = multierror.Append(err, fmt.Errorf("role set raw bindings cannot be empty string"))
	//	}
	//
	//	switch rs.SecretType {
	//	case SecretTypeAccessToken:
	//		if rs.TokenGen == nil {
	//			err = multierror.Append(err, fmt.Errorf("access token role set should have initialized token generator"))
	//		} else if len(rs.TokenGen.Scopes) == 0 {
	//			err = multierror.Append(err, fmt.Errorf("access token role set should have defined scopes"))
	//		}
	//	case SecretTypeKey:
	//		break
	//	default:
	//		err = multierror.Append(err, fmt.Errorf("unknown secret type: %s", rs.SecretType))
	//	}
	return err.ErrorOrNil()
}

//

func (rs *IdentityRole) save(ctx context.Context, s logical.Storage) error {
	if err := rs.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesetStoragePrefix, rs.Name), rs)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}
