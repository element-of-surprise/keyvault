// Package secrets provides a client for interacting with Keyvault's secret storage.
package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/element-of-surprise/keyvault/ops"
	"github.com/element-of-surprise/keyvault/ops/secret"
	"github.com/element-of-surprise/keyvault/ops/values"
)

// Secrets provides methods for extracting secrets from keyvault.
type Secrets struct {
	Ops *ops.REST
}

type getOptions struct {
	version      string
	base64Decode bool
}

// GetOption is an optional argument for the Get() or Bundle() call.
type GetOption func(o *getOptions)

// AtVersion specifies the particular version of a secret you want. By default this is the latest version.
func AtVersion(version string) GetOption {
	return func(o *getOptions) {
		o.version = version
	}
}

// Base64Decode causes the string returned by Keyvault to be base64 decoded. This should be used when binary
// data (such as a certificate private key) was stored and not a regular string.
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
	bundle, err := s.Ops.Secrets().Get(ctx, name, co.version)
	if err != nil {
		return nil, bundle, err
	}

	var decoded []byte
	if co.base64Decode {
		decoded, err = base64.StdEncoding.DecodeString(bundle.Value)
		if err != nil {
			return nil, Bundle{}, fmt.Errorf("Secrets.Get(%s): value could not be base64 decoded: %w", name, err)
		}
	} else {
		decoded = []byte(bundle.Value)
	}

	return decoded, bundle, nil
}

// Versions returns a list of version information for a secret.
func (s Secrets) Versions(ctx context.Context, name string, maxResults int32) ([]secret.Version, error) {
	return s.Ops.Secrets().Versions(ctx, name, maxResults)
}

// List returns a list of all secrets in the vault.
func (s Secrets) List(ctx context.Context, maxResults int32) ([]string, error) {
	vers, err := s.Ops.Secrets().List(ctx, maxResults)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vers))
	for _, ver := range vers {
		out = append(out, ver.ID)
	}
	return out, nil
}

type caller int

const (
	unknownCaller caller = iota
	set
	update
)

type applier interface {
	apply(caller caller, co interface{})
}

// applierFunc is an adapter that turns the wrapped function into
// a CallOption. Implements CallOption.
type applierFunc func(caller, interface{})

func (c applierFunc) apply(caller caller, co interface{}) {
	c(caller, co)
}

type ChangeOption interface {
	applier

	setOption()
	updateOption()
}

// SetOption is an option for the Set() method.
type SetOption interface {
	applier
	setOption()
}

// setOption implements applier and SetOption.
type setOption struct {
	applier
}

func (s setOption) setOption() {}

// UpdateOption is an option for the UpdateAttr() method.
type UpdateOption interface {
	applier
	updateOption()
}

// changeOption implememnts applier, SetOption and UpdateOption.
type changeOption struct {
	applier
}

func (c changeOption) setOption()    {}
func (c changeOption) updateOption() {}

// ContentType sets the ContentType field to ct. Implements SetOption and UpdateOption.
func ContentType(ct string) ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).ContentType = ct
			},
		),
	}
}

// Tags sets key/value pairs for the tags field of the secret. Implements SetOption and UpdateOption.
func Tags(tags map[string]string) ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).Tags = tags
			},
		),
	}
}

// Recoverylevel sets the level of recovery for this password when deleted. Implements SetOption and UpdateOption.
func RecoveryLevel(drl secret.DeletionRecoveryLevel) ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).Attributes.RecoveryLevel = drl
			},
		),
	}
}

// RecoverableDays is the soft delete data retention. Must be set to
// >=7 and <=90.
func RecoverableDays(days int) ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).Attributes.RecoverableDays = days
			},
		),
	}
}

// Enabled enables the secret.
func Enabled() ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).Attributes.Enabled = true
			},
		),
	}
}

// NotBefore indiates that the key isn't valid before this time.
func NotBefore(t time.Time) ChangeOption {
	return changeOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				v := values.Time(t.UTC())
				co.(*secret.UpdateSetRequest).Attributes.NotBefore = v
			},
		),
	}
}

// Base64Encode indicates that the value being passed to Set() represents binary data (not string data) and should be
// encoded to allow for transport.
func Base64Encode() SetOption {
	return setOption{
		applier: applierFunc(
			func(caller caller, co interface{}) {
				co.(*secret.UpdateSetRequest).Base64Encode = true
			},
		),
	}
}

// Set creates a new secret or adds a new version of a secret if it already exists. SetOption is also implemented
// by ChangeOption. If value does not represent a string (it represents binary data), you should pass Base64Encode().
func (s Secrets) Set(ctx context.Context, name string, value []byte, options ...SetOption) error {
	req := secret.UpdateSetRequest{}
	for _, o := range options {
		o.apply(set, &req)
	}

	if req.Base64Encode {
		req.Value = base64.StdEncoding.EncodeToString(value)
	} else {
		req.Value = string(value)
	}

	_, err := s.Ops.Secrets().Set(ctx, name, req)
	if err != nil {
		return fmt.Errorf("Secrets().Set(%s) operation failed: %w", name, err)
	}
	return nil
}

// UpdateAttr updates a secret's attributes. UpdateOption is also implemented by ChangeOption.
func (s Secrets) UpdateAttr(ctx context.Context, name, version string, options ...UpdateOption) error {
	req := secret.UpdateSetRequest{}
	for _, o := range options {
		o.apply(update, &req)
	}

	_, err := s.Ops.Secrets().UpdateAttr(ctx, name, version, req)
	if err != nil {
		return fmt.Errorf("Secrets().UpdateAttr(%s) operation failed: %w", name, err)
	}
	return nil
}

// Delete deletes the secret with name "name".
func (s Secrets) Delete(ctx context.Context, name string) error {
	_, err := s.Ops.Secrets().Delete(ctx, name)
	if err != nil {
		return fmt.Errorf("Secrets.Delete(%s) operation failed: %w", name, err)
	}
	return nil
}

type DeletedBundle = secret.DeletedBundle

// Deleted returns information about a deleted secret.
func (s Secrets) Deleted(ctx context.Context, name string) (DeletedBundle, error) {
	return s.Ops.Secrets().Deleted(ctx, name)
}

type Deleted = secret.Deleted

// ListDeleted returns a list of deleted secrets.
func (s Secrets) ListDeleted(ctx context.Context, maxResults int32) ([]Deleted, error) {
	return s.Ops.Secrets().ListDeleted(ctx, maxResults)
}

// Backup returns a string representing a blob of all versions of a secret. This is in an undisclosed format.
func (s Secrets) Backup(ctx context.Context, name string) (string, error) {
	return s.Ops.Secrets().Backup(ctx, name)
}

// Purge permanently deletes a secret, without the possibility of recovery. Name is the name of a deleted secret.
func (s Secrets) Purge(ctx context.Context, name string) error {
	return s.Ops.Secrets().Purge(ctx, name)
}

// Restore restores a key from the value passed. That vlaue comes from a call to Backup().
func (s Secrets) Restore(ctx context.Context, value string) (Bundle, error) {
	return s.Ops.Secrets().Restore(ctx, value)
}

// Recover recovers a deleted secret that has not been purged to the latest version.
func (s Secrets) Recover(ctx context.Context, name string) (Bundle, error) {
	return s.Ops.Secrets().Recover(ctx, name)
}
