package azuresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const walAppKey = "appCreate"
const walSpKey = "spCreate"

// Eventually expire the WAL if for some reason the rollback operation consistently fails
var maxWALAge = 24 * time.Hour

type walApp struct {
	AppID      string
	AppObjID   string
	Expiration time.Time
}

type walSp struct {
	ObjID      string
	Expiration time.Time
}

func (b *azureSecretBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walAppKey:
		// Decode the WAL data
		var entry walApp
		d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
			Result:     &entry,
		})
		if err != nil {
			return err
		}
		err = d.Decode(data)
		if err != nil {
			return err
		}

		client, err := b.getClient(ctx, req.Storage)
		if err != nil {
			return err
		}

		b.Logger().Debug("rolling back application", "appID", entry.AppID, "appObjID", entry.AppObjID)

		// Attempt to delete the application. deleteApplication doesn't return an error if
		// the app isn't found, so no special handling is needed for that case. If we don't
		// succeed within maxWALAge (e.g. client creds have changed and the delete will never
		// succeed), unconditionally remove the WAL.
		if err := client.deleteApplication(ctx, entry.AppObjID); err != nil {
			b.Logger().Warn("rollback error deleting application", "err", err)

			if time.Now().After(entry.Expiration) {
				return nil
			}
			return err
		}
	case walSpKey:
		// Decode the WAL data
		var entry walSp
		d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
			Result:     &entry,
		})
		if err != nil {
			return err
		}
		err = d.Decode(data)
		if err != nil {
			return err
		}

		client, err := b.getClient(ctx, req.Storage)
		if err != nil {
			return err
		}

		b.Logger().Debug("rolling back service principal", "objID", entry.ObjID)

		// Attempt to delete the service principal. deleteServicePrincipal doesn't return an error
		// if the app isn't found, so no special handling is needed for that case. If we don't
		// succeed within maxWALAge (e.g. client creds have changed and the delete will never
		// succeed), unconditionally remove the WAL.
		if err := client.deleteServicePrincipal(ctx, entry.ObjID); err != nil {
			b.Logger().Warn("rollback error deleting service principal", "err", err)

			if time.Now().After(entry.Expiration) {
				return nil
			}
			return err
		}
	default:
		return fmt.Errorf("unknown rollback type %q", kind)
	}

	return nil
}
