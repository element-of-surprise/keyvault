package keyvault

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/element-of-surprise/keyvault/auth"
	"github.com/element-of-surprise/keyvault/ops"
	"github.com/element-of-surprise/keyvault/secrets"

	aauth "github.com/Azure/go-autorest/autorest/azure/auth"
)

// CloudEndpoint is an endpoint address to use when doing authenication with MSI.
type CloudEndpoint string

const (
	// PublicCloud is Azure's public cloud endpoint.
	PublicCloud CloudEndpoint = "https://vault.azure.net/"
)

// MSIAuth provides authentication to Keyvault by an Azure's Managed Service Identity. Simply
// provide the MSI's clientID. This is the only secure method of accessing a Keyvault.
// An auth package is available for doing other authorization methods, but every other method (at this time)
// would require storing a secret or cert to access the Keyvault in another secret store.
// Note: If using Kubernetes, pods do not get access to MSI by default, it requires: https://github.com/Azure/aad-pod-identity .
func MSIAuth(clientID string, endpoint CloudEndpoint) (auth.Authorization, error) {
	conf := &aauth.MSIConfig{
		Resource: strings.TrimSuffix(string(endpoint), "/"),
		ClientID: clientID,
	}
	a, err := conf.Authorizer()
	if err != nil {
		return auth.Authorization{}, err
	}
	return auth.Authorization{Authorizer: a}, nil
}

// Client is a client for interacting with KeyVault.
type Client struct {
	ops *ops.REST
}

// New creates a new Keyvault Client. vault is the name of the
// Keyvault. endpoint is the CloudEndpoint (usually PublicCloud).
// auth can be created normally with MSIAuth().
func New(vault string, endpoint CloudEndpoint, auth auth.Authorization) (*Client, error) {
	if err := auth.Validate(); err != nil {
		return nil, err
	}

	base, err := url.Parse(string(endpoint))
	if err != nil {
		return nil, fmt.Errorf("keyvault.New() could not parse CloudEndpoint %q: %w", endpoint, err)
	}
	base.Host = fmt.Sprintf("%s.%s", vault, base.Host)

	rest, err := ops.New(base.String(), auth.Authorizer)
	if err != nil {
		return nil, err
	}
	return &Client{ops: rest}, nil
}

// Ops returns the underlying REST client that this package uses
// underneath to access KeyVault. Use this only when this client
// does not support an operation you require, as the REST client
// is not normally meant to be interacted with.
func (c *Client) Ops() *ops.REST {
	return c.ops
}

// Secrets returns an object for doing Secrets operations.
func (c *Client) Secrets() secrets.Secrets {
	return secrets.Secrets{c.ops}
}

// TLS returns an object for doing common TLS operations.
func (c *Client) TLS() TLS {
	return TLS{c.Secrets()}
}
