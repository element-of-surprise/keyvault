// Package tls provides options for retrieving TLS certificates and tranforming them into Go representation that can
// be used with the standard library tls package.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/element-of-surprise/keyvault/secrets"

	mypkcs12 "github.com/johnsiilver/getcert/pkcs12"
)

// ArchiveFromat indicates what type of certificate archive format is used to encode a certificate.
type ArchiveFormat int

const (
	// UnknownArchiveFormat indicates the archive format is unknown.
	UnknownArchiveFormat               = 0
	// PCKS12 indicates the certificate is in the PKCS12 format.
	PKCS12               ArchiveFormat = 1
	// PEM indicates the certificate is in the PEM format.
	PEM                  ArchiveFormat = 2
)

// TLS provides methods for extracting TLS certificates for use in TLS wrapped communication.
type TLS struct {
	SecretClient secrets.Secrets
}

type privateKeyOption struct {
	version string
}

// PrivateKeyOption is an optional argument for PrivateKey().
type PrivateKeyOption func(o *privateKeyOption)

// PKVersion sets a specific secret to retrieve with PrivateKey().
func PKVersion(version string) PrivateKeyOption {
	return func(o *privateKeyOption) {
		o.version = version
	}
}

// PrivateKey returns the private key after it has been bases64 decoded.
// If trying to use this with TLS for a net.HTTP server, ServerCert() is probably what you want.
func (t TLS) PrivateKey(ctx context.Context, name string, options ...PrivateKeyOption) (ArchiveFormat, []byte, error) {
	co := privateKeyOption{}
	for _, o := range options {
		o(&co)
	}

	gopts := []secrets.GetOption{secrets.Base64Decode()}
	if co.version != "" {
		gopts = append(gopts, secrets.AtVersion(co.version))
	}

	decoded, bundle, err := t.SecretClient.Get(ctx, name, gopts...)
	if err != nil {
		return UnknownArchiveFormat, nil, err
	}

	var af ArchiveFormat
	switch strings.ToLower(bundle.ContentType) {
	case "application/x-pkcs12":
		af = PKCS12
	case "application/x-pem-file":
		af = PEM
	}

	return af, decoded, nil
}

type serviceCertOptions struct {
	version    string
	skipVerify bool
}

// ServiceCertOption is an optional argument for ServiceCert().
type ServiceCertOption func(o *serviceCertOptions)

// SCVersion specifies the cert version you want to use. Defaults to the latest.
func SCVersion(version string) ServiceCertOption {
	return func(o *serviceCertOptions) {
		o.version = version
	}
}

// SCSkipVerify skips verification of a certificate. This is useful when dealing with self-signed certificates which are
// useful in testing scenarios. Be wary of this option in any other case, as you using a tls.Cerificate for content
// you are sending that cannot be validated against a CA (meaning clients in non-mTLS scenarios cannot validate its you).
// If your organization doesn't have a CA or you want simplified TLS certs, consider https://letsencrypt.org/.
func SCSkipVerify() ServiceCertOption {
	return func(o *serviceCertOptions) {
		o.skipVerify = true
	}
}

/*
ServerCert returns a tls.Certificate that can be used to send content over TLS. This may fail if the public certificate
chain does not adhere to some type of order.

Here is a quick way to use the cert in a Golang HTTP server(does not deal with TLS cert expirations):

	cert, err := kv.TLS().ServiceCert(ctx, "certname")
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
*/
func (t TLS) ServiceCert(ctx context.Context, name string, options ...ServiceCertOption) (tls.Certificate, error) {
	co := serviceCertOptions{}
	for _, o := range options {
		o(&co)
	}
	pkopts := []PrivateKeyOption{}
	if co.version != "" {
		pkopts = append(pkopts, PKVersion(co.version))
	}

	af, data, err := t.PrivateKey(ctx, name, pkopts...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not retrieve private key information for cert %q: %w", name, err)
	}

	var tlsCert tls.Certificate
	switch af {
	case PKCS12:
		_, _, tlsCert, err = mypkcs12.FromBytes(data, "", co.skipVerify)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("problems decoding private key(%s) in PKCS12 format: %w", name, err)
		}
	default:
		return tlsCert, fmt.Errorf("ServiceCert does not support a cert in format %v", af)
	}
	return tlsCert, nil
}
