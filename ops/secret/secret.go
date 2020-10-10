// Package secret provides a client for REST operations involving secrets.
// This implements calls from this API: https://docs.microsoft.com/en-us/rest/api/keyvault/#secret-operations
package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	//"strconv"

	"github.com/element-of-surprise/keyvault/ops/internal/conn"
	"github.com/element-of-surprise/keyvault/ops/values"
)

// DeletionRecoveryLevel indicates what level of recovery is associated with a particular secret.
// Details at: https://docs.microsoft.com/en-us/rest/api/keyvault/getsecretversions/getsecretversions#deletionrecoverylevel
type DeletionRecoveryLevel string

func (d DeletionRecoveryLevel) MarshalJSON() ([]byte, error) {
	return []byte(d), nil
}

func (d *DeletionRecoveryLevel) UnmarshalJSON(s []byte) error {
	v := DeletionRecoveryLevel(strings.Trim(string(s), `"`))
	if !validDeletionRecoveryLevel[v] {
		return fmt.Errorf("%q is an unrecognized DeletionRecoveryLevel", v)
	}
	*d = v
	return nil
}

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

var validDeletionRecoveryLevel = map[DeletionRecoveryLevel]bool{
	Purgeable:                        true,
	Recoverable:                      true,
	RecoverableProtectedSubscription: true,
	RecoverablePurgeable:             true,
}

// Base contains the base attributes used in multiple return objects.
type Base struct {
	// Attributes are attributes tied to a Bundle.
	Attributes *Attributes
	// ContentType is a string that can optionally be set by a user to indicate the content type.
	// This is not a definitive content type given by the system.
	ContentType string `json:"contentType"`
	// ID is the secret"s ID.
	ID string `json:"id"`
	// Tags are application specific metadata in the form of key-value pairs.
	Tags map[string]string `json:"tags"`
}

// Bundle is used to describe a secret.
type Bundle struct {
	*Base

	// KID specifies the corresponding key backing the KV certificate. This is only set if this is a secret backing a KV certificate,
	KID string `json:"kid"`
	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
	// Value is the value of the secret.
	// Note: Keyvault uses special secrets that are created when storing certificates with private keys. If this is the private key chain, this will be base64 encoded binary data.
	Value string `json:"value"`
}

// Version describes a secret version.
type Version struct {
	*Base

	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
}

// DeletedBundle is returned when we delete a bundle.
type DeletedBundle struct {
	*Bundle

	// DeleteDate is the time when the secret was deleted.
	DeleteDate values.Time `json:"deletedDate"`
	// RecoveryID is the url of the recovery object, used to identify and recover the deleted secret.
	RecoveryID *values.URL `json:"recoveryId"`
	// ScheduledPurgeDate is the time when the secret is scheduled to be purged.
	ScheduledPurgeDate values.Time `json:"scheduledPurgeDate"`
}

// Attributes are attributes associated with this secret.
type Attributes struct {
	// RecoveryLevel is the level of recovery for this password when deleted.  See the description of
	// DeletionRecoveryLevel above.
	RecoveryLevel DeletionRecoveryLevel `json:"recoveryLevel"`
	// RecoverableDays is the soft delete data retention days. Must be >=7 and <=90, otherwise 0.
	RecoverableDays int `json:"recoverableDays"`
	// Enabled indicates if the secret is currently enabled.
	Enabled bool `json:"enabled"`
	// Created indicates the time the secret was created in UTC. If set to the zero value, it indicates
	// this was not set.
	Created *values.Time `json:"created"`
	// NotBefore indicate that the key isn"t valid before this time in UTC. If set to the zero value, it indicates
	// this was not set.
	NotBefore values.Time `json:"nbf"`
	// Updated indicates the last time the secret was updated in UTC. If set to the zero value, it indicates
	// this was not set.
	Updated values.Time `json:"updated"`
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

// AtVersion provides the secret version for a call. Can be used in GetSecret().
func AtVersion(ver string) Option {
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

	err := c.Conn.Call(ctx, conn.Get, path.String(), nil, nil, &bundle)
	return bundle, err
}

type listResult struct {
	NextLink string    `json:"nextLink"`
	Value    []Version `json:"value"`
}

// Versions returns a list of version information for a secret from the service.
func (c *Client) Versions(ctx context.Context, name string, maxResults int32) ([]Version, error) {
	if maxResults <= 0 {
		maxResults = 25
	}

	versions := []Version{}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name + "/versions")
	for {
		qv := url.Values{}
		//qv.Add("maxresults", strconv.Itoa(int(maxResults)))

		result := listResult{}
		err := c.Conn.Call(ctx, conn.Get, path.String(), qv, nil, &result)
		if err != nil {
			return nil, fmt.Errorf("issue getting list of secret versions for %q: %w", name, err)
		}
		versions = append(versions, result.Value...)
		if result.NextLink != "" {
			path.Reset()
			path.WriteString(result.NextLink)
			continue
		}
		break
	}
	return versions, nil
}

// List returns a list of all secrets in the vault. We use the Version type, which is based on the SecretListResult type
// in the REST API.
func (c *Client) List(ctx context.Context, maxResults int32) ([]Version, error) {
	if maxResults <= 0 {
		maxResults = 25
	}

	versions := []Version{}

	path := strings.Builder{}
	path.WriteString("/secrets")
	for {
		qv := url.Values{}
		//qv.Add("maxresults", strconv.Itoa(int(maxResults)))

		result := listResult{}
		err := c.Conn.Call(ctx, conn.Get, path.String(), qv, nil, &result)
		if err != nil {
			return nil, fmt.Errorf("issue getting list of secrets: %w", err)
		}
		versions = append(versions, result.Value...)
		if result.NextLink != "" {
			path.Reset()
			path.WriteString(result.NextLink)
			continue
		}
		break
	}
	return versions, nil
}

// SetRequest is used to request a new secret.
type SetRequest struct {
	// Attributes are attributes tied to a Bundle.
	Attributes *Attributes
	// ContentType is a string that can optionally be set by a user to indicate the content type.
	// This is not a definitive content type given by the system.
	ContentType string `json:"contentType"`
	// Tags are application specific metadata in the form of key-value pairs.
	Tags map[string]string `json:"tags"`
	// Value is the value of the secret.
	Value string
}

// Set creates a new secret or adds a new version if the named secret exists.
func (c *Client) Set(ctx context.Context, name string, req SetRequest) (Bundle, error) {
	bundle := Bundle{}
	if req.Value == "" {
		return bundle, fmt.Errorf("secret.SetRequest() request must provide a value")
	}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name)

	b, err := json.Marshal(req)
	if err != nil {
		return bundle, fmt.Errorf("bug: ops.Secret.Set() cannot marshal a SetRequest: %w", err)
	}

	err = c.Conn.Call(ctx, conn.Put, path.String(), nil, bytes.NewBuffer(b), &bundle)
	return bundle, err
}

// Delete deletes the named secret and returns information the deleted secret.
func (c *Client) Delete(ctx context.Context, name string) (DeletedBundle, error) {
	bundle := DeletedBundle{}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name)

	err := c.Conn.Call(ctx, conn.Delete, path.String(), nil, nil, &bundle)
	return bundle, err
}
