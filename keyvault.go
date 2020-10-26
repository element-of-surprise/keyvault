/*
Package keyvault provides access to Azure's Keyvault service.

For details on the keyvault service, see: https://azure.microsoft.com/en-us/services/key-vault/

For general information on the XML API: https://docs.microsoft.com/en-us/rest/api/keyvault/

Below are some examples of using common sub-packages. For more detailed
information, options and examples, see the individual packages.


Creating a client with MSI authorizer

To begin using this package, create an Authorizer and a client targeting your keyvault endpoint:
	msi, err := keyvault.MSIAuth(msiClientID, keyvault.PublicCloud)
	if err != nil {
		// Do something
	}

	// This creates your client. The "vaultName" is a standin fo
	// your unique vault name (not the FQDN).
	client, err := keyvault.New("vaultName", keyvault.PublicCloud, msi)
	if err != nil {
		// Do something
	}


Accessing a text secret

You can access a secret by accessing the secret package and calling a method:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, _, err := client.Secrets().Get(ctx, "text-secret")
	if err != nil {
		// Do something
	}
	fmt.Println(string(secret))


Accessing a binary secret

Some secrets represent binary data Base64 encoded. Retrieval is simple:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, _, err := client.Secrets().Get(ctx, "binary-secret", secrets.Base64Decode())
	if err != nil {
		// Do something
	}

Retrieve a TLS cert for Golang webserver

Getting a TLS cert to serve up for a Golang HTTP server is easy:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// We automatically deal with PKCS12 or PEM decoding.
	cert, _, err := client.TLS().ServiceCert(ctx, "certname")
	if err != nil {
		// Do something
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
*/
package keyvault

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/element-of-surprise/keyvault/auth"
	"github.com/element-of-surprise/keyvault/ops"
	"github.com/element-of-surprise/keyvault/secrets"
	"github.com/element-of-surprise/keyvault/tls"

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
func (c *Client) TLS() tls.TLS {
	return tls.TLS{SecretClient: c.Secrets()}
}
