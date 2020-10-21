// Package certs provides a client for REST operations involving certificates.
// This implemenets calls from this API: https://docs.microsoft.com/en-us/rest/api/keyvault/#certificate-operations
package certs

import (
	"context"
	"fmt"
	//"net/url"
	"strings"
	//"strconv"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"

	"github.com/element-of-surprise/keyvault/ops/internal/conn"
	"github.com/element-of-surprise/keyvault/ops/values"
)

// DeletionRecoveryLevel indicates what level of recovery is associated with a particular certificate.
// Details at: https://docs.microsoft.com/en-us/rest/api/keyvault/getcertificate/getcertificate#deletionrecoverylevel
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
	// Customized indicates a vault state in which deletion is 
	// recoverable without the possibility for immediate and 
	// permanent deletion (i.e. purge when 7<= 
	// SoftDeleteRetentionInDays < 90).This level guarantees 
	// the recoverability of the deleted entity during the 
	// retention interval and while the subscription is still 
	// available.
	Customized DeletionRecoveryLevel = "CustomizedRecoverable"

	// CustomizedProtected indicates a vault and subscription 
	// state in which deletion is recoverable, immediate 
	// and permanent deletion (i.e. purge) is not permitted, 
	// and in which the subscription itself cannot be 
	// permanently canceled when 7<= SoftDeleteRetentionInDays 
	// < 90. This level guarantees the recoverability of the 
	// deleted entity during the retention interval, and also 
	// reflects the fact that the subscription itself cannot 
	// be cancelled.
	CustomizedProtected = "CustomizedRecoverable+ProtectedSubscription"

	// CustomizedPurgeable indicates a vault state in which 
	// deletion is recoverable, and which also permits 
	// immediate and permanent deletion (i.e. purge when 
	// 7<= SoftDeleteRetentionInDays < 90). This level 
	// guarantees the recoverability of the deleted entity 
	// during the retention interval, unless a Purge operation 
	// is requested, or the subscription is cancelled.
	CustomizedPurgeable = "CustomizedRecoverable+Purgeable"

	// Purgeable indicates a vault state in which deletion is 
	// an irreversible operation, without the possibility for 
	// recovery. This level corresponds to no protection 
	// being available against a Delete operation; the data is 
	// irretrievably lost upon accepting a Delete operation at 
	// the entity level or higher (vault, resource group, 
	// subscription etc.)
	Purgeable DeletionRecoveryLevel = "Purgeable"
	// Recoverable indicates a vault state in which deletion 
	// is recoverable without the possibility for immediate 
	// and permanent deletion (i.e. purge). This level 
	// guarantees the recoverability of the deleted entity 
	// during the retention interval(90 days) and while the 
	// subscription is still available. System wil permanently 
	// delete it after 90 days, if not recovered.
	Recoverable DeletionRecoveryLevel = "Recoverable"
	// RecoverableProtectedSubscription indicates a vault 
	// and subscription state in which deletion is recoverable 
	// within retention interval (90 days), immediate and 
	// permanent deletion (i.e. purge) is not permitted, and 
	// in which the subscription itself cannot be permanently 
	// canceled. System wil permanently delete it after 
	// 90 days, if not recovered.
	RecoverableProtectedSubscription DeletionRecoveryLevel = "Recoverable+ProtectedSubscription"
	// RecoverablePurgeable indicates a vault state in which 
	// deletion is recoverable, and which also permits immediate 
	// and permanent deletion (i.e. purge). This level guarantees
	// the recoverability of the deleted entity during the 
	// retention interval (90 days), unless a Purge operation 
	// is requested, or the subscription is cancelled. System 
	// wil permanently delete it after 90 days, if not recovered.
	RecoverablePurgeable DeletionRecoveryLevel = "Recoverable+Purgeable"
)

var validDeletionRecoveryLevel = map[DeletionRecoveryLevel]bool{
	Customized: true,
	CustomizedProtected: true,
	CustomizedPurgeable: true,
	Purgeable:                        true,
	Recoverable:                      true,
	RecoverableProtectedSubscription: true,
	RecoverablePurgeable:             true,
}

// Attributes are attributes associated with a certificate.
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
	// Expiry is the expiry date of the certificate.
	Expiry values.Time `json:"exp,omitempty"`
}

type Base struct {

}

type Bundle struct {
	Attributes Attributes `json:"attributes,omitempty"`
	// CER is the PEM contents of the x509 certificate. 
	CER string `json:"cer"`
	// Certs are the X509 certificates converted from the CER field.
	Certs []*x509.Certificate `json:"-"`
	// ContentType is the content type of the secret.
	// TODO(jdoak): I think this is a copy paste bug in their documentation. 
	// Unless it is telling me the private key archive format that is in the secret store.
	ContentType string `json:"contentType,omitempty"`
	// ID is the id of the certificate.
	ID string `json:"id"`
	// KID is the key id.
	KID string `json:"kid,omitempty"`
	// Policy is the management policy.
	Policy Policy `json:"policy,omitempty"`
	// SID is the secret id that stores the private key.
	SID string `json:"sid,omitempty"`
	// Tags are application specific metadata key/value pairs.
	Tags map[string]string `json:"tags,omitempty"`
	// Thumbprint is the thumbprint of the certificate.
	Thumbprint string `json:"x5t,omitempty"`
}

// X590 takes the .CER attribute and decodes it into X509 certificates
// so that users may inspect the certificates for information, adds certs
// to certificate pools, etc...
func (b Bundle) X509() error {
	var data []byte
	// Sometimes the data is base64 encoded, in those cases decode it.
	p12, err := base64.StdEncoding.DecodeString(b.CER)
	if err == nil {
		data = p12
	}

	blocks := []*pem.Block{}
	for {
		block, data := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("CERToX509() had issue finding a PEM block in content")
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		blocks = append(blocks, block)
		if len(data) == 0 {
			break
		}
	}
	if len(blocks) == 0 {
		return fmt.Errorf("CERTox509() could not locate any public keys in PEM")
	}

	certs := []*x509.Certificate{}
	for i, block := range blocks{
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("block %d did not appear to be a x509 certificate: %w", i, err)
		}
		certs = append(certs, cert)
	}
	b.Certs = certs
	return nil
}

// Policy is the management policy for a certificate.
type Policy struct {
	// Attributes are the certificate attributes.
	Attributes Attributes `json:"attributes,omitempty"`
	// ID is the id of the certificate.
	ID string `json:"id"`
	// Issuer is parameters for the issuer of the X509 component of a certificate.
	Issuer IssuerParams `json:"issuer"`
	// KeyProps is the properties of the key backing a certificate.
	KeyProps KeyProps `json:"key_props"`
	// LifetimeActions are actions that will be performed by Key Vault over the lifetime of a certificate.
	LifetimeActions []LifetimeAction `json:"lifetime_actions"`
	// SecretPops is properites of the secret backing a certificate.
	SecretProps SecretProps `json:"secret_props"`
	// X509Props are properties of the X509 component of a certificate.
	X509Props X509Props `json:"x509_props"`
}

// IssuerParams is the parameters of the X509 component of a certificate.
type IssuerParams struct {
	// Transparency indicates if the certificates generated under this policy should be published to certificate transparency logs.
	Transparency bool `json:"cert_transparency"`
	// Type is the certificate type as supported by the provider (optional); for example 'OV-SSL', 'EV-SSL'.
	Type string `json:"cty"`
	// Name of the referenced issuer object or reserved names; for example, 'Self' or 'Unknown'.
	Name string
}

// KeyProps is the properties of the key pair backing a certificate.
type KeyProps struct {
	// CurveName is the elliptical curve name.
	CurveName CurveName `json:"crv"`
	// Exportable indicates if the private key can be exported.
	Exportable bool `json:"exportable"`
	// Size is the key size in bits. For example: 2048, 3072, or 4096 for RSA.
	Size int `json:"key_size"`
	// Type is the type of key pair to be used for the certificate.
	Type KeyType `json:"kty"`
	// ReuseKey indicates if the same key pair will be used on certificate renewal.
	ReuseKey bool `json:"reuse_key"`
}

// CurveName is the elliptical curve name.
// There is virtually no data on the fields or what they contain in the documentation.
// https://docs.microsoft.com/en-us/rest/api/keyvault/createcertificate/createcertificate#jsonwebkeycurvename
type CurveName struct {
	P256 string `json:"P-256"`
	P256K string `json:"P-256K"`
	P384 string `json:"P-384"`
	P521 string `json:"P-521"`
}

// KeyType is the type of key pair to be used for the certificate.
// There is vritually no data on the fields or what they contain in the documentation.
// https://docs.microsoft.com/en-us/rest/api/keyvault/createcertificate/createcertificate#jsonwebkeytype
type KeyType struct {
	EC string `json:"EC"`
	ECHSM string `json:"EC-HSM"`
	RSA string `json:"RSA"`
	RSAHSM string `json:"RSA-HSM"`
	OCT string `json:"oct"`
}

// LifetimeAction is an action and a trigger that will be performed over the lifetime of a certificate.
type LifetimeAction struct {
	// Action is the action that will be executed.
	Action Action `json:"action"`
	// Trigger is the trigger that will trigger the action.
	Trigger Trigger `json:"trigger"`
}

// Action is the action that will be executed by Keyvault.
type Action struct {
	// ActionType is the type of action.
	ActionType ActionType `json:"action_type"`
}

// ActionType is the type of action. What goes in the fields is not documented:
// https://docs.microsoft.com/en-us/rest/api/keyvault/createcertificate/createcertificate#actiontype
type ActionType struct {
	AutoRenew string `json:"AutoRenew"`
	EmailContacts string `json:"EmailContacts"`
}

// Trigger represents a condition to be satisfied for an action to be executed.
type Trigger struct {
	// DaysUntilExpiry is the days before expiry to attempt renewal. 
	// Value should be between 1 and validity_in_months multiplied by 27. 
	// If validity_in_months is 36, then value should be between 1 and 972 (36 * 27).
	DaysUntilExpiry int `json:"days_before_expiry"`
	// LifetimePercentage is the percentage of lifetime at which to trigger. Value should be between 1 and 99.
	LifetimePercentage int `json:"lifetime_percentage"`
}

// SecretProps is the properties of the secret holding the private key.
type SecretProps struct {
	// ContentType is the media type (MIME type) of the secret key (also known as the private key).
	ContentType string `json:"contentType"`
}

// X509Props is the properties of the X509 certificate.
type X509Props struct {
	// EKUS is the enhanced key usage.
	EKUS []string `json:"ekus"`
	// KeyUsage is a list of key usages.
	KeyUsage []string `json:"key_usage"`
	// SANS is the subject alternative names.
	SANS SubjectAlternativeNames `json:"sans"`
	// Subject is the subject name. Should be a valid x509 distiguished name.
	Subject string `json:"subject"`
	// ValidityMonths is the duration in months that the certificate is valid.
	ValidityMonths int `json:"validity_months"`
}

// SubjectAlternativeNames are the subject alternate names of a X509 object.
type SubjectAlternativeNames struct {
	// DNSNames are DNS names.
	DNSNames []string `json:"dns_names"`
	// Emails are email addresses.
	Emails []string `json:"emails"`
	// UPNS are user principal names.
	UPNS []string `json:"upns"`
}

// Client is a client for making calls to Certificate operations on Keyvault.
type Client struct {
	// Conn is the connection to the keyvault service.
	Conn *conn.Conn
}

type backupResult struct {
	Value string `json:"value"`
}

// Backup requests that a backup of the specified certificate be downloaded to the client.
// All versions of the certificate will be downloaded. The backups are encapsulated in the
// returned string. The format is not specified.
func (c *Client) Backup(ctx context.Context, name string) (string, error) {
	path := strings.Builder{}
	path.WriteString(fmt.Sprintf("/certificates/%s/backup", name))

	result := backupResult{}

	err := c.Conn.Call(ctx, conn.Post, path.String(), nil, nil, &result)
	if err != nil {
		return "", err
	}
	return result.Value, nil
}

// Create creates a new certificate. If this is the first version, the certificate resource is created.
func (c *Client) Create(ctx context.Context, name string, attr Attributes, policy Policy, tags map[string]string) {

}

func (c *Client) Delete(ctx context.Context) {

}

func (c *Client) DeleteContacts(ctx context.Context) {

}

func (c *Client) DeleteIssuer(ctx context.Context) {

}

func (c *Client) DeleteOperation(ctx context.Context) {

}

func (c *Client) Certificate(ctx context.Context) {
	
}

func (c *Client) Contacts(ctx context.Context) {

}

func (c *Client) Issuer(ctx context.Context) {

}

func (c *Client) Operation(ctx context.Context) {

}

func (c *Client) Policy(ctx context.Context) {

}

func (c *Client) Versions(ctx context.Context) {

}

func (c *Client) Certificates(ctx context.Context) {

}

func (c *Client) Deleted(ctx context.Context) {

}

func (c *Client) ListDeleted(ctx context.Context) {

}

func (c *Client) Import(ctx context.Context) {

}

func (c *Client) Merge(ctx context.Context) {

}

func (c *Client) Purge(ctx context.Context) {

}

func (c *Client) Recover(ctx context.Context) {

}

func (c *Client) Restore(ctx context.Context) {

}

func (c *Client) SetContacts(ctx context.Context) {

}

func (c *Client) SetIssuer(ctx context.Context) {

}

func (c *Client) Update(ctx context.Context) {

}

func (c *Client) UpdateIssuer(ctx context.Context) {

}

func (c *Client) UpdateOperation(ctx context.Context) {

}

func (c *Client) UpdatePolicy(ctx context.Context) {

}
