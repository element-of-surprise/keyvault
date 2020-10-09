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
	bundle, err := s.client.Ops().Secrets().GetSecret(ctx, name, secret.Version(version))
	if err != nil {
		return "", err
	}
	return bundle.Value, nil
}

// Bundle will return the entire SecretBundle for a secret
// which contains metadata about the Secret.
func (s Secrets) Bundle(ctx context.Context, name string, version string) (secret.Bundle, error) {
	return s.client.Ops().Secrets().GetSecret(ctx, name, secret.Version(version))
}
