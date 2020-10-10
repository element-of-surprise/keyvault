package keyvault

import (
	"context"

	"github.com/element-of-surprise/keyvault/ops/secret"
)

// Secrets provides methods for extracting secrets from keyvault.
type Secrets struct {
	client *Client
}

// Get gets a secret stored at name. This is used to get secrets that represent string values.
// A string can represent binary data, as this REST call is oversubscribed to provide certificate private
// keys. In those cases, the data is base64 encoded. If doing TLS, you should use keyvault.TLS instead.
// If doing other certs, you should use keyvault.Certs instead.
func (s Secrets) Get(ctx context.Context, name string, version string) (string, error) {
	bundle, err := s.client.Ops().Secrets().GetSecret(ctx, name, secret.AtVersion(version))
	if err != nil {
		return "", err
	}
	return bundle.Value, nil
}

// Bundle will return the entire SecretBundle for a secret
// which contains metadata about the Secret.
func (s Secrets) Bundle(ctx context.Context, name string, version string) (secret.Bundle, error) {
	return s.client.Ops().Secrets().GetSecret(ctx, name, secret.AtVersion(version))
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
