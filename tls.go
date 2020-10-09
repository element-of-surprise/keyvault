// TODO(jdoak): Remove all places where we pass version, make it an option.
package keyvault

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"

	mypkcs12 "github.com/johnsiilver/getcert/pkcs12"
)

// ArchiveFromat indicates what type of certificate archive format is used to encode a certificate.
type ArchiveFormat int8

const (
	UnknownArchiveFormat               = 0
	PKCS12               ArchiveFormat = 1
	PEM                  ArchiveFormat = 2
)

// TLS provides methods for extracting TLS certificates for use in TLS wrapped communication.
type TLS struct {
	client *Client
}

// PrivateKey returns the private key after it has been bases64 decoded.
// If trying to use this with TLS for a net.HTTP server, ServerCert() is probably what you want.
func (t TLS) PrivateKey(ctx context.Context, name, version string) (ArchiveFormat, []byte, error) {
	bundle, err := t.client.Secrets().Bundle(ctx, name, version)
	if err != nil {
		return UnknownArchiveFormat, nil, err
	}

	data, err := base64.StdEncoding.DecodeString(bundle.Value)
	if err != nil {
		return UnknownArchiveFormat, nil, fmt.Errorf("problem base64 decoding our private key: %w", err)
	}

	// TODO(jdoak): Add detection of the ArchiveFormat.
	return PKCS12, data, nil
}

/*
ServerCert returns a tls.Certificate that can be used to serve content over TLS. This may fail if the public certificate
chain does not adhere to some type of order.

Here is a quick way to use the cert in your service(does not deal with TLS cert expirations):

	cert, err := kv.TLS().ServiceCert(ctx, "certname", LatestVersion)
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
func (t TLS) ServiceCert(ctx context.Context, name, version string, skipVerify bool) (tls.Certificate, error) {
	_, data, err := t.PrivateKey(ctx, name, version)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not retrieve private key information for cert %q: %w", name, err)
	}
	// TODO(jdoak): Handle non-pkcs12 data.
	_, _, tlsCert, err := mypkcs12.FromBytes(data, "", skipVerify)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("problems decoding private key(%s) in PKCS12 format: %w", name, err)
	}
	return tlsCert, nil
}
