package keyvault

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/element-of-surprise/keyvault/ops/secret"
	"github.com/element-of-surprise/keyvault/ops/values"
)

// Secrets provides methods for extracting secrets from keyvault.
type Secrets struct {
	client *Client
}

type getOptions struct {
	version      string
	base64Decode bool
}

// GetOption is an optional argument for the Get() or Bundle() call.
type GetOption func(o *getOptions)

// GetVersion specifies the particular version of a secret you want. By default this is the latest version.
func GetVersion(version string) GetOption {
	return func(o *getOptions) {
		o.version = version
	}
}

// Base64Decode indicates that data is binary, so it should be based64 decoded.
func Base64Decode() GetOption {
	return func(o *getOptions) {
		o.base64Decode = true
	}
}

type Bundle = secret.Bundle

// Get gets a secret stored at name. This is used to get secrets stored in Keyvault.
// A string can represent binary data, as this REST call is oversubscribed to provide certificate private
// keys. In those cases, the data is base64 encoded(a method to store binary data as string data).
// If doing TLS, you should use keyvault.TLS() instead. If doing other certs, you should use keyvault.Certs instead.
// Returns the data (which will be Base64 decoded if Base64Decode() option is passed) and the Bundle containing
// the metadata and original .Value as sent by the server (no decoding).
func (s Secrets) Get(ctx context.Context, name string, options ...GetOption) ([]byte, Bundle, error) {
	co := getOptions{}
	for _, o := range options {
		o(&co)
	}
	bundle, err := s.client.Ops().Secrets().GetSecret(ctx, name, co.version)
	if err != nil {
		return nil, bundle, err
	}

	var b []byte
	if co.base64Decode {
		b, err = base64.StdEncoding.DecodeString(bundle.Value)
		if err != nil {
			return nil, Bundle{}, fmt.Errorf("secret content could not be base64 decoded: %w", err)
		}
	} else {
		b = []byte(bundle.Value)
	}

	return b, bundle, nil
}

// Versions returns a list of version information for a secret.
func (s Secrets) Versions(ctx context.Context, name string, maxResults int32) ([]secret.Version, error) {
	return s.client.Ops().Secrets().Versions(ctx, name, maxResults)
}

// List returns a list of all secrets in the vault.
func (s Secrets) List(ctx context.Context, maxResults int32) ([]string, error) {
	vers, err := s.client.Ops().Secrets().List(ctx, maxResults)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vers))
	for _, ver := range vers {
		out = append(out, ver.ID)
	}
	return out, nil
}

// SetOption provides an optional argument to the Set command.
type SetOption func(req *secret.SetRequest)

// ContentType sets the ContentType field to ct.
func ContentType(ct string) SetOption {
	return func(req *secret.SetRequest) {
		req.ContentType = ct
	}
}

// Tags sets key/value pairs for the tags field of the secret.
func Tags(tags map[string]string) SetOption {
	return func(req *secret.SetRequest) {
		req.Tags = tags
	}
}

// Recoverylevel sets the level of recovery for this password when deleted.
func RecoveryLevel(drl secret.DeletionRecoveryLevel) SetOption {
	return func(req *secret.SetRequest) {
		if req.Attributes == nil {
			req.Attributes = &secret.Attributes{}
		}
		req.Attributes.RecoveryLevel = drl
	}
}

// RecoverableDays is the soft delete data retention. Must be set to
// >=7 and <=90.
func RecoverableDays(days int) SetOption {
	return func(req *secret.SetRequest) {
		if req.Attributes == nil {
			req.Attributes = &secret.Attributes{}
		}
		req.Attributes.RecoverableDays = days
	}
}

// Enabled enables the secret.
func Enabled() SetOption {
	return func(req *secret.SetRequest) {
		if req.Attributes == nil {
			req.Attributes = &secret.Attributes{}
		}
		req.Attributes.Enabled = true
	}
}

// NotBefore indiates that the key isn't valid before this time.
func NotBefore(t time.Time) SetOption {
	return func(req *secret.SetRequest) {
		if req.Attributes == nil {
			req.Attributes = &secret.Attributes{}
		}
		v := values.Time(t.UTC())
		req.Attributes.NotBefore = v
	}
}

// Base64Encode indicates that your value being set is binary data and
// not string data, therefore it should be base64 encoded in order
// to be stored correctly.
func Base64Encode() SetOption {
	return func(req *secret.SetRequest) {
		req.Base64Encode = true
	}
}

// Set creates a new secret or adds a new version of a secret if it already exists.
func (s Secrets) Set(ctx context.Context, name string, value []byte, options ...SetOption) error {
	req := secret.SetRequest{}
	for _, o := range options {
		o(&req)
	}

	var v string
	if req.Base64Encode {
		v = base64.StdEncoding.EncodeToString(value)
	} else {
		v = string(value)
	}
	req.Value = v
	_, err := s.client.Ops().Secrets().Set(ctx, name, req)
	return err
}
