// Package secret provides a client for REST operations involving secrets.
// This implements calls from this API: https://docs.microsoft.com/en-us/rest/api/keyvault/#secret-operations
package secret

import (
	"context"
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
	return []byte(fmt.Sprintf("%q", d)), nil
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
	Attributes Attributes
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
	Base

	// KID specifies the corresponding key backing the KV certificate. This is only set if this is a secret backing a KV certificate,
	KID string `json:"kid"`
	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
	// Value is the value of the secret.
	Value string `json:"value"`
}

// Version describes a secret version.
type Version struct {
	Base

	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
}

// DeletedBundle is returned when we delete a bundle.
type DeletedBundle struct {
	Bundle

	// DeleteDate is the time when the secret was deleted.
	DeleteDate values.Time `json:"deletedDate"`
	// RecoveryID is the url of the recovery object, used to identify and recover the deleted secret.
	RecoveryID *values.URL `json:"recoveryId"`
	// ScheduledPurgeDate is the time when the secret is scheduled to be purged.
	ScheduledPurgeDate values.Time `json:"scheduledPurgeDate"`
}

// Deleted is a deleted secret.
type Deleted struct {
	Base

	// Managed indicates if a secret"s lifetime is managed by keyvault.
	// If this is a secret backing a certificate, this will be true.
	Managed bool `json:"managed"`
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
	RecoveryLevel DeletionRecoveryLevel `json:"recoveryLevel,omitempty"`
	// RecoverableDays is the soft delete data retention days. Must be >=7 and <=90, otherwise 0.
	RecoverableDays int `json:"recoverableDays,omitempty"`
	// Enabled indicates if the secret is currently enabled.
	Enabled bool `json:"enabled,omitempty"`
	// Created indicates the time the secret was created in UTC. If set to the zero value, it indicates
	// this was not set.
	Created *values.Time `json:"created,omitempty"`
	// NotBefore indicate that the key isn"t valid before this time in UTC. If set to the zero value, it indicates
	// this was not set.
	NotBefore values.Time `json:"nbf,omitempty"`
	// Updated indicates the last time the secret was updated in UTC. If set to the zero value, it indicates
	// this was not set.
	Updated values.Time `json:"updated,omitempty"`
}

// Client is a client for making calls to Secret operations on Keyvault.
type Client struct {
	// Conn is the connection to the keyvault service.
	Conn *conn.Conn
}

// GetSecret gets a secret with the name "name" from Keyvault. If you wish to get a secret at a certain version,
// pass the Version() option.
func (c *Client) Get(ctx context.Context, name string, version string) (Bundle, error) {
	bundle := Bundle{}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name)
	if version != "" {
		path.WriteString("/" + version)
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

// UpdateSetRequest is used to set a secret or update its attributes.
type UpdateSetRequest struct {
	// Attributes are attributes tied to a Bundle.
	Attributes *Attributes `json:",omitempty"`
	// ContentType is a string that can optionally be set by a user to indicate the content type.
	// This is not a definitive content type given by the system.
	ContentType string `json:"contentType,omitempty"`
	// Tags are application specific metadata in the form of key-value pairs.
	Tags map[string]string `json:"tags,omitempty"`
	// Value is the value of the secret. Only valid in a Set.
	Value string `json:"value,omitempty"`

	// Base64Encode indicates to base64 encode the value.
	Base64Encode bool `json:"-"`
}

// Set creates a new secret or adds a new version if the named secret exists.
func (c *Client) Set(ctx context.Context, name string, req UpdateSetRequest) (Bundle, error) {
	bundle := Bundle{}
	if req.Value == "" {
		return bundle, fmt.Errorf("secret.SetRequest() request must provide a value")
	}

	path := strings.Builder{}
	path.WriteString("/secrets/" + name)

	err := c.Conn.Call(ctx, conn.Put, path.String(), nil, req, &bundle)
	return bundle, err
}

// UpdateAttr updates a secret's attributes.
func (c *Client) UpdateAttr(ctx context.Context, name, version string, req UpdateSetRequest) (Bundle, error) {
	bundle := Bundle{}

	if version == "" {
		return bundle, fmt.Errorf("UpdateAttr requires a version, passed empty string")
	}

	path := strings.Builder{}
	path.WriteString(fmt.Sprintf("/secrets/%s/%s", name, version))

	err := c.Conn.Call(ctx, conn.Patch, path.String(), nil, req, &bundle)
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

// Deleted returns information on a deleted secret.
func (c *Client) Deleted(ctx context.Context, name string) (DeletedBundle, error) {
	bundle := DeletedBundle{}

	path := strings.Builder{}
	path.WriteString("/deletedsecrets/" + name)

	err := c.Conn.Call(ctx, conn.Get, path.String(), nil, nil, &bundle)
	return bundle, err
}

type deletedListResult struct {
	NextLink string    `json:"nextLink"`
	Value    []Deleted `json:"value"`
}

// ListDeleted returns a list of deleted secrets.
func (c *Client) ListDeleted(ctx context.Context, maxResults int32) ([]Deleted, error) {
	if maxResults <= 0 {
		maxResults = 25
	}

	deleted := []Deleted{}

	path := strings.Builder{}
	path.WriteString("/secrets")
	for {
		qv := url.Values{}
		//qv.Add("maxresults", strconv.Itoa(int(maxResults)))

		result := deletedListResult{}
		err := c.Conn.Call(ctx, conn.Get, path.String(), qv, nil, &result)
		if err != nil {
			return nil, fmt.Errorf("issue getting list of deleted secrets: %w", err)
		}
		deleted = append(deleted, result.Value...)
		if result.NextLink != "" {
			path.Reset()
			path.WriteString(result.NextLink)
			continue
		}
		break
	}
	return deleted, nil
}
