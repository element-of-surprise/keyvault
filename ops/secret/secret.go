// Package secret provides a client for REST operations involving secrets.
// This implements calls from this API: https://docs.microsoft.com/en-us/rest/api/keyvault/#secret-operations
package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"log"

	"github.com/element-of-surprise/keyvault/ops/internal/conn"
)

// DeletionRecoveryLevel indicates what level of recovery is associated with a particular secret.
// Details at: https://docs.microsoft.com/en-us/rest/api/keyvault/getsecretversions/getsecretversions#deletionrecoverylevel
type DeletionRecoveryLevel string

const (
	// Purgeable indicates soft-delete is not enabled for this vault. A DELETE operation results in immediate and
	// irreversible data loss.
	Purgeable DeletionRecoveryLevel = "Purgeable"
	// Recoverable indicates soft-delete is enabled for this vault and purge has been disabled. A deleted entity
	// will remain in this state until recovered, or the end of the retention interval.
	Recoverable DeletionRecoveryLevel = "Recoverable"
	// RecoverableProtectedSubscription indicates soft-delete is enabled for this vault, and the subscription is
	// protected against immediate deletion.
	RecoverableProtectedSubscription DeletionRecoveryLevel = "Recoverable+ProtectedSubscription"
	// RecoverablePurgeable indicates soft-delete is enabled for this vault; A privileged user may trigger an
	// immediate, irreversible deletion(purge) of a deleted entity.
	RecoverablePurgeable DeletionRecoveryLevel = "Recoverable+Purgeable"
)

// Bundle is returned by Keyvault when accessing secrets.
type Bundle struct {
	// Attributes are attributes tied to a Bundle.
	Attributes *Attributes
	// ContentType is a string that can optionally be set by a user to indicate the content type.
	// This is not a definitive content type given by the system.
	ContentType string `json:"contentType"`
	// ID is the secret"s ID.
	ID string `json:"id"`
	// KID specifies the corresponding key backing the KV certificate. This is only set if this is a secret backing a KV certificate,
	KID string `json:"kid"`
	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
	// Tags are application specific metadata in the form of key-value pairs.
	Tags map[string]string `json:"tags"`
	// Value is the value of the secret.
	// Note: Keyvault uses special secrets that are created when storing certificates with private keys. If this is the private key chain, this will be base64 encoded binary data.
	Value string `json:"value"`
}

// Attributes are attributes associated with this secret.
type Attributes struct {
	// RecoveryLevel the level of recovery for this password when deleted.  See the description of
	// DeletionRecoveryLevel above.
	RecoveryLevel DeletionRecoveryLevel `json:"recoveryLevel"`
	// RecoverableDays is the soft delete data retention days. Must be >=7 and <=90, otherwise 0.
	RecoverableDays int `json:"recoverableDays"`
	// Enabled indicates if the secret is currently enabled.
	Enabled bool `json:"enabled"`
	// Created indicates the time the secret was created in UTC. If set to the zero value, it indicates
	// this was not set.
	Created time.Time `json:"created"`
	// NotBefore indicate that the key isn"t valid before this time in UTC. If set to the zero value, it indicates
	// this was not set.
	NotBefore time.Time `json:"nbf"`
	// Updated indicates the last time the secret was updated in UTC. If set to the zero value, it indicates
	// this was not set.
	Updated time.Time `json:"updated"`
}

// MarshalJSON implements json.Marshaller. This is not covered by any compatibility promise.
func (s *Attributes) MarshalJSON() ([]byte, error) {
	sa := struct {
		RecoveryLevel   DeletionRecoveryLevel `json:"recoveryLevel"`
		RecoverableDays int                   `json:"recoverableDays"`
		Enabled         bool                  `json:"enabled"`
		Created         int                   `json:"created"`
		NotBefore       int                   `json:"nbf"`
		Updated         int                   `json:"updated"`
	}{
		RecoveryLevel:   s.RecoveryLevel,
		RecoverableDays: s.RecoverableDays,
		Enabled:         s.Enabled,
		Created:         int(s.Created.Unix()),
		NotBefore:       int(s.NotBefore.Unix()),
		Updated:         int(s.Updated.Unix()),
	}

	return json.Marshal(sa)
}

// saFields is a map of json names to the related struct field.
// generated on startup so this is a one time operation.
var saFields = map[string]reflect.StructField{}

func init() {
	t := reflect.TypeOf(Attributes{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" {
			log.Println("empty tag")
			continue
		}
		name := strings.Split(tag, ",")[0]
		saFields[name] = t.Field(i)
	}
}

// Unmarshal implements json.Unmarshaller. This is not covered by any compatibility promise.
func (s *Attributes) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	m := map[string]interface{}{}

	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("unabled to unmarshal Attributes: %w", err)
	}

	sa := reflect.ValueOf(s).Elem()

	fieldWasSet := false
	for k, i := range m {
		// Lookup the json field name, if we don"t have it then its most likely a new field.
		// We just skip it then, because our struct doesn"t support it.
		sf := saFields[k]
		if sf.Name == "" {
			continue
		}

		// Ok, we need to do a conversion if the field is a time.Time.
		switch sf.Type.Name(){
		case "Time":
			v, ok := i.(float64)
			if !ok {
				return fmt.Errorf("Attributes was unable to unmarshal field %q because it was storing a %T, not a float64", k, i)
			}
			if v == 0 {
				continue
			}
			timer := time.Unix(int64(v), 0)
			sa.FieldByName(sf.Name).Set(reflect.ValueOf(timer))
			fieldWasSet = true
			continue
		case "DeletionRecoveryLevel":
			fieldWasSet = true
			sa.FieldByName(sf.Name).Set(reflect.ValueOf(DeletionRecoveryLevel(i.(string))))
			continue
		}

		// All our other fields we can simply just set.
		fieldWasSet = true
		sa.FieldByName(sf.Name).Set(reflect.ValueOf(i))
	}

	if !fieldWasSet {
		return fmt.Errorf("received a Attributes, but no fields decoded. Likely a bug in the decoder:\n%s", string(b))
	}
	return nil
}

// Client is a client for making calls to Secret operations on Keyvault.
type Client struct {
	// Conn is the connection to the keyvault service.
	Conn *conn.Conn
}

type caller int32

const (
	unknownCaller   = 0
	getSecretCaller = 1
)

type callOpts struct {
	getSecret getSecretOpts
}

type getSecretOpts struct {
	version string
}

// Options is an optional argument to a call.
type Option func(*callOpts, caller) error

// Version provides the secret version for a call. Can be used in GetSecret().
func Version(ver string) Option {
	return func(co *callOpts, caller caller) error {
		switch caller {
		case getSecretCaller:
			co.getSecret.version = ver
			return nil
		}
		return fmt.Errorf("Version option is not supported in this call")
	}
}

// GetSecret gets a secret with the name "name" from Keyvault. If you wish to get a secret at a certain version,
// pass the Version() option.
func (c *Client) GetSecret(ctx context.Context, name string, options ...Option) (Bundle, error) {
	bundle := Bundle{}

	co := callOpts{}
	for _, o := range options {
		if err := o(&co, getSecretCaller); err != nil {
			return bundle, fmt.Errorf("GetSecret() call error: %w", err)
		}
	}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name)
	if co.getSecret.version != "" {
		path.WriteString("/" + co.getSecret.version)
	}

	err := c.Conn.Call(ctx, path.String(), nil, nil, &bundle)
	return bundle, err
}
