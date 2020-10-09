// Package ops provide access to REST Keyvault operations via the REST API.
package ops

import (
	"github.com/element-of-surprise/keyvault/ops/internal/conn"
	"github.com/element-of-surprise/keyvault/ops/secret"

	"github.com/Azure/go-autorest/autorest"
)

// REST is a REST client for doing operations against the REST API.
// This client and its methods are thread-safe.
type REST struct {
	conn *conn.Conn
}

// New creates a new REST client for operations against Keyvault.
// This is the underlying client to our SDK and simply implements
// the raw REST calls without any of nice helpers of the SDK.
func New(endpoint string, auth autorest.Authorizer) (*REST, error) {
	c, err := conn.New(endpoint, auth)
	if err != nil {
		return nil, err
	}
	return &REST{conn: c}, nil
}

// Secrets returns a client for doing secret operations.
func (r *REST) Secrets() *secret.Client {
	return &secret.Client{Conn: r.conn}
}
