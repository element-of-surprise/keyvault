// Package certs provides a client for REST operations involving certificates.
// This implemenets calls from this API: https://docs.microsoft.com/en-us/rest/api/keyvault/#certificate-operations
package certs

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"

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
	Customized:                       true,
	CustomizedProtected:              true,
	CustomizedPurgeable:              true,
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

var zeroAttributes = Attributes{}

func (a Attributes) isZero() bool {
	if a == zeroAttributes {
		return true
	}
	return false
}

// Base is base attributes of a certificate bundle.
type Base struct {
	Attributes Attributes `json:"attributes,omitempty"`
	// ID is the id of the certificate.
	ID string `json:"id"`
	// Tags are application specific metadata key/value pairs.
	Tags map[string]string `json:"tags,omitempty"`
	// Thumbprint is the thumbprint of the certificate.
	Thumbprint string `json:"x5t,omitempty"`
}

// Bundle is a certificate bundle.
type Bundle struct {
	Base
	// CER is the PEM contents of the x509 certificate.
	CER string `json:"cer"`
	// Certs are the X509 certificates converted from the CER field.
	Certs []*x509.Certificate `json:"-"`
	// ContentType is the content type of the secret.
	// TODO(jdoak): I think this is a copy paste bug in their documentation.
	// Unless it is telling me the private key archive format that is in the secret store.
	ContentType string `json:"contentType,omitempty"`
	// KID is the key id.
	KID string `json:"kid,omitempty"`
	// Policy is the management policy.
	Policy Policy `json:"policy,omitempty"`
	// SID is the secret id that stores the private key.
	SID string `json:"sid,omitempty"`
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
	for i, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("block %d did not appear to be a x509 certificate: %w", i, err)
		}
		certs = append(certs, cert)
	}
	b.Certs = certs
	return nil
}

// DeletedBundle is a deleted certificate consisting of its previous ID, attributes, tags and all information on when it will be purged.
type DeletedBundle struct {
	Bundle
	// Deleted is the time when the certificate was deleted.
	Deleted values.Time `json:"deletedDate"`
	// ScheduledPurge is when the certificate is scheduled to be purged.
	ScheduledPurge values.Time `json:"scheduledPurgeDate"`
	// RecoveryID is the url of the recovery object used to recovery the deleted certificate.
	RecoveryID string `json:"recoveryId"`
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

// Issuer details information about the certificate issuer.
type Issuer struct {
	// Attributes is the attributes of the issuer.
	Attributes IssuerAttr `json:"attributes"`
	// Credentials is the credentials to be used for the issuer.
	Credentials IssuerCreds `json:"credentials"`
	// ID is issuer id.
	ID string `json:"id"`
	// Org details the organization provided to the issuer.
	Org Org `json:"org_details"`
	// Provider is the issuer provider.
	Provider string `json:"provider"`
}

// IssuerAttr represents attributes of an Issuer.
type IssuerAttr struct {
	// Created is the time the issuer was created.
	Created values.Time `json:"created"`
	// Updated is the last time the issuer was updatd.
	Updated values.Time `json:"updated"`
	// Enabled indicates if the issuer is enabled.
	Enabled bool `json:"enabled"`
}

// IssuerCreds is the credentials to be used for the certificate issuer.
type IssuerCreds struct {
	// ID is the username/account name/account id.
	ID string `json:"account_id"`
	// Secret is the password/secret/account key.
	Secret string `json:"pwd"`
}

// Org provides details on an organization's certificate issuer.
type Org struct {
	// AdminDetails provides details about the org's administrators.
	AdminDetails []AdminDetails `json:"admin_details"`
	// ID is the id of the organization.
	ID string `json:"id"`
}

// AdminDetails provides contact information for an org's administrator.
type AdminDetails struct {
	// Email provides the email address of an administrator.
	Email string `json:"email"`
	// First is the admin's first name.
	First string `json:"first_name"`
	// Last is the admin's last name.
	Last string `json:"last_name"`
	// Phone is the amdin's phone number.
	Phone string `json:"phone"`
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
	P256  string `json:"P-256"`
	P256K string `json:"P-256K"`
	P384  string `json:"P-384"`
	P521  string `json:"P-521"`
}

// KeyType is the type of key pair to be used for the certificate.
// There is vritually no data on the fields or what they contain in the documentation.
// https://docs.microsoft.com/en-us/rest/api/keyvault/createcertificate/createcertificate#jsonwebkeytype
type KeyType struct {
	EC     string `json:"EC"`
	ECHSM  string `json:"EC-HSM"`
	RSA    string `json:"RSA"`
	RSAHSM string `json:"RSA-HSM"`
	OCT    string `json:"oct"`
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
	AutoRenew     string `json:"AutoRenew"`
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

// KVError is a keyvault error. KVError implements error.
type KVError struct {
	// Code is the error code.
	Code string `json:"code"`
	// InnerError is the inner error.
	InnerError *KVError `json:"innererror"`
	// Message is the error message.
	Message string `json:"message"`
}

// Error implements error.Error().
func (k KVError) Error() string {
	b, _ := json.Marshal(k) // Unlikely that an error would happen + there is nothing to do but panic or log, which we can't
	return string(b)
}

// Unwrap implements errors.Unwrap().
func (k KVError) Unwrap() error {
	if k.InnerError != nil {
		return k.InnerError
	}
	return nil
}

// Operation provides details on the certificate operation performed.
type Operation struct {
	// Cancellation indicates if cancellation was requested on the certificate operation.
	Cancellation bool `json:"cancellation_requested"`
	// CSR is the certificate signing request (CSR) that is being used in the certificate operation.
	CSR string `json:"csr"`
	// Error is the error encountered, if any, during the certificate operation.
	Error KVError `json:"error"`
	// ID is the certificate ID.
	ID string `json:"id"`
	// Issuer is the parameters for the issuer of the X509 component of a certificate.
	Issuer IssuerParams `json:"issuer"`
	// RequestID is the identifier for the certificate operation.
	RequestID string `json:"request_id"`
	// Status is the status of the certificate operation.
	Status string `json:"status"`
	// StatusDetails is the details of the certificate operation.
	StatusDetails string `json:"status_details"`
	// Target is the location which contains the result of the certificate operation.
	Target string `json:"target"`
}

// Contact contains the contact information for the vault certificates.
type Contact struct {
	// Name is the person's name.
	Name string `json:"name"`
	// Email is the contact's email.
	Email string `json:"email"`
	// Phone is the contact's phone.
	Phone string `json:"phone"`
}

// Contacts contas the contacts for the vault certificates.
type Contacts struct {
	// Contacts is the list of contacts for the vault certificates.
	Contacts []Contact `json:"contacts"`
	// ID is the identifier for the contacts collection.
	ID string `json:"id"`
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
func (c *Client) Create(ctx context.Context, name string, attr Attributes, policy Policy, tags map[string]string) (Operation, error) {
	path := strings.Builder{}
	path.WriteString(fmt.Sprintf("/certificates/%s/create", name))

	body := struct {
		Attributes Attributes        `json:"attributes,omitempty"`
		Policy     Policy            `json:"policy"`
		Tags       map[string]string `json:"tags"`
	}{
		Attributes: attr,
		Policy:     policy,
		Tags:       tags,
	}

	result := Operation{}

	err := c.Conn.Call(ctx, conn.Post, path.String(), nil, body, &result)
	return result, err
}

// Delete deletes the named certificate.
func (c *Client) Delete(ctx context.Context, name string) (DeletedBundle, error) {
	path := strings.Builder{}
	path.WriteString("/certificates/" + name)

	bundle := DeletedBundle{}

	err := c.Conn.Call(ctx, conn.Delete, path.String(), nil, nil, &bundle)
	return bundle, err
}

// TODO(jdoak): REST API looks wrong, waiting for information from kv team.
/*
func (c *Client) DeleteContacts(ctx context.Context) {
	path := strings.Builder{}
        path.WriteString("/certificates/contacts")

	bundle := DeletedBundle{}

	err := c.Conn.Call(ctx, conn.Delete, path.String(), nil, nil, &DeletedBundle)
	return bundle, err
}
*/

// DeleteIssuer removes the specified issuer from the vault.
func (c *Client) DeleteIssuer(ctx context.Context, name string) (Issuer, error) {
	path := strings.Builder{}
	path.WriteString("/certificates/issuers/" + name)

	bundle := Issuer{}

	err := c.Conn.Call(ctx, conn.Delete, path.String(), nil, nil, &bundle)
	return bundle, err
}

// jdoak: This is something that must be for the portal or something. Basically, you want to kill the creation of
// certificate you have in progress. Unless someone contacts us with a need for this, I'm going to leave this
// as a placeholder as to why its not implemented.
/*
func (c *Client) DeleteOperation(ctx context.Context) {

}
*/

// Certificate gets the named verion of a certificate's information.
func (c *Client) Certificate(ctx context.Context, name, version string) (Bundle, error) {
	path := fmt.Sprintf("/certificates/%s/%s", name, version)

	bundle := Bundle{}

	err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &bundle)
	return bundle, err
}

// Contacts returns a list of contact information.
func (c *Client) Contacts(ctx context.Context) (Contacts, error) {
	path := "/certificates/contacts"

	contacts := Contacts{}

	err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &contacts)
	return contacts, err
}

// Issuer lists the specified certificate issuer. Name is the name of the issuer.
func (c *Client) Issuer(ctx context.Context, name string) (Issuer, error) {
	path := fmt.Sprintf("/certificates/issuers/%s", name)

	bundle := Issuer{}

	err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &bundle)
	return bundle, err
}

// CertificateIssuerItem is a certificate issuer for a keyvault.
type CertificateIssuerItem struct {
	// ID is the ID of the issuer.
	ID string `json:"id"`
	// Provider is the issuer provider.
	Provider string `json:"provider"`
}

// Issuers returns a list of Issuers for this Keyvault.
func (c *Client) Issuers(ctx context.Context) ([]CertificateIssuerItem, error) {
	path := "/certificates/issuers"

	result := struct {
		NextLink string                  `json:"nextLink"`
		Value    []CertificateIssuerItem `json:"value"`
	}{}

	results := []CertificateIssuerItem{}
	for {
		err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &result)
		if err != nil {
			return nil, err
		}
		results = append(results, result.Value...)
		if result.NextLink == "" {
			break
		}
		path = result.NextLink
	}
	return results, nil
}

// jdoak: This is something that must be for the portal or something. Basically, you want to get info on a certificate operation
// in progress. Unless someone contacts us with a need for this, I'm going to leave this as a placeholder as to why its not implemented.
/*
func (c *Client) Operation(ctx context.Context) {

}
*/

// Policy lists the policy for a certificate.
func (c *Client) Policy(ctx context.Context, name string) (Policy, error) {
	path := fmt.Sprintf("/certificates/%s/policy", name)

	bundle := Policy{}

	err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &bundle)
	return bundle, err
}

// Versions returns information about versions of a certificate.
func (c *Client) Versions(ctx context.Context, name string) ([]Base, error) {
	path := fmt.Sprintf("/certificates/%s/versions", name)

	result := struct {
		NextLink string `json:"nextLink"`
		Value    []Base `json:"value"`
	}{}

	results := []Base{}
	for {
		err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &result)
		if err != nil {
			return nil, err
		}
		results = append(results, result.Value...)
		if result.NextLink == "" {
			return results, nil
		}
		path = result.NextLink
	}
	return results, nil
}

// ListCertificates lists certificates in the vault. includePending indicates if the list should
// include certificates that are pending. maxResults, if not set, will be 25.
func (c *Client) ListCertificates(ctx context.Context, includePending bool, maxResults int32) ([]Base, error) {
	path := "/certificates"

	qv := url.Values{}
	qv.Add("includePending", strconv.FormatBool(includePending))
	if maxResults > 0 {
		// qv.Add("maxresults", maxResults)
	}

	result := struct {
		NextLink string `json:"nextLink"`
		Value    []Base `json:"value"`
	}{}

	results := []Base{}
	for {
		err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &result)
		if err != nil {
			return nil, err
		}
		results = append(results, result.Value...)
		if result.NextLink == "" {
			return results, nil
		}
		path = result.NextLink
	}
	return results, nil
}

// Deleted retrieves information about the specified deleted certificate.
func (c *Client) Deleted(ctx context.Context, name string) (DeletedBundle, error) {
	path := fmt.Sprintf("/deletedcertificates/%s", name)

	bundle := DeletedBundle{}

	err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &bundle)
	return bundle, err

}

// DeletedCertMeta provides data about a deleted certificate.
type DeletedCertMeta struct {
	Attributes Attributes        `json:"attributes"`
	Deleted    values.Time       `json:"deletedDate"`
	ID         string            `json:"id"`
	RecoveryID string            `json:"recoveryId"`
	Scheduled  values.Time       `json:"scheduledPurgeDate"`
	Tags       map[string]string `json:"tags"`
	Thumbprint string            `json:"x5t"`
}

func (c *Client) ListDeleted(ctx context.Context, includePending bool, maxResults int32) ([]DeletedCertMeta, error) {
	path := "/deletedcertificates"

	qv := url.Values{}
	qv.Add("includePending", strconv.FormatBool(includePending))
	if maxResults > 0 {
		// qv.Add("maxresults", maxResults)
	}

	result := struct {
		NextLink string            `json:"nextLink"`
		Value    []DeletedCertMeta `json:"value"`
	}{}

	results := []DeletedCertMeta{}
	for {
		err := c.Conn.Call(ctx, conn.Get, path, nil, nil, &result)
		if err != nil {
			return nil, err
		}
		results = append(results, result.Value...)
		if result.NextLink == "" {
			return results, nil
		}
		path = result.NextLink
	}
	return results, nil

}

type importReq struct {
	Attributes *Attributes       `json:"attributes,omitempty"`
	Policy     *Policy           `json:"policy,omitempty"`
	PWD        string            `json:"pwd,omitempty"`
	Tags       map[string]string `json:"tags"`
	Value      string            `json"value"`
}

// ImportOption is an option for Import().
type ImportOption func(i *importReq)

// ImportAttr provides attributes for an imported certificate.
func ImportAttr(a Attributes) ImportOption {
	return func(i *importReq) {
		i.Attributes = &a
	}
}

// ImportPolicy provides a policy for an imported certificate.
func ImportPolicy(p Policy) ImportOption {
	return func(i *importReq) {
		i.Policy = &p
	}
}

// ImportPassword provides a password if the private key is encrypted for a PFX(PKCS12) certificate.
func ImportPassword(s string) ImportOption {
	return func(i *importReq) {
		i.PWD = s
	}
}

// ImportTags are tags to be attached to the certificate in Keyvault.
func ImportTags(t map[string]string) ImportOption {
	return func(i *importReq) {
		i.Tags = t
	}
}

// Import imports a certificate into Keyvault. This can be either a PKCS12 file or PEM file.
// If it is PKCS12, must be base64 encoded and use option ImportPassword() if it has a passsword
// associated with it.
func (c *Client) Import(ctx context.Context, name string, value string, options ...ImportOption) (Bundle, error) {
	path := fmt.Sprintf("/certificates/%s/import", name)

	bundle := Bundle{}

	body := importReq{Value: value}
	for _, o := range options {
		o(&body)
	}

	err := c.Conn.Call(ctx, conn.Post, path, nil, body, &bundle)
	return bundle, err
}

type mergeReq struct {
	Attributes *Attributes       `json:"attributes,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	X5C        []string          `json:"x5c"`
}

// MergeOption is an option to Merge().
type MergeOption func(m *mergeReq)

// MergeAttr provides attributes for a Merge().
func MergeAttr(a Attributes) MergeOption {
	return func(m *mergeReq) {
		m.Attributes = &a
	}
}

// MergeTags provides tags for a Merge().
func MergeTags(t map[string]string) MergeOption {
	return func(m *mergeReq) {
		m.Tags = t
	}
}

// Merge merges a certificate or chain with a key pair existing on the server. Name is the
// name of the certificate. x5c is the certificate or chain to merge.
func (c *Client) Merge(ctx context.Context, name string, x5c []string, options ...MergeOption) (Bundle, error) {
	path := fmt.Sprintf("/certificates/%s/pending/merge", name)

	bundle := Bundle{}

	body := mergeReq{X5C: x5c}
	for _, o := range options {
		o(&body)
	}

	err := c.Conn.Call(ctx, conn.Post, path, nil, body, &bundle)
	return bundle, err
}

// Purge permanently deletes the specified deleted certificate without possibility for recovery.
func (c *Client) Purge(ctx context.Context, name string) error {
	path := fmt.Sprintf("/deletedcertificates/%s", name)

	err := c.Conn.Call(ctx, conn.Delete, path, nil, nil, nil)
	return err
}

// Recover recovers the deleted certificate back to its current version.
func (c *Client) Recover(ctx context.Context, name string) (Bundle, error) {
	path := fmt.Sprintf("/deletedcertificates/%s/recover", name)

	bundle := Bundle{}

	err := c.Conn.Call(ctx, conn.Post, path, nil, nil, &bundle)
	return bundle, err
}

// Restore restores a backed up certificate to the vault. backup is the string provided
// by keyvault when calling Backup().
func (c *Client) Restore(ctx context.Context, backup string) (Bundle, error) {
	path := "/certificates/restore"

	bundle := Bundle{}

	body := struct {
		Value string `json:"value"`
	}{
		Value: backup,
	}

	err := c.Conn.Call(ctx, conn.Post, path, nil, body, &bundle)
	return bundle, err
}

// SetContacts sets the certificate contacts for the vault.
func (c *Client) SetContacts(ctx context.Context, contacts []Contact) (Contacts, error) {
	path := "/certificates/contacts"

	bundle := Contacts{}

	body := struct {
		Contacts []Contact `json:"contacts"`
	}{
		Contacts: contacts,
	}

	err := c.Conn.Call(ctx, conn.Post, path, nil, body, &bundle)
	return bundle, err
}

// SetIssuer sets the specified certificate issuer.
func (c *Client) SetIssuer(ctx context.Context, issuer Issuer) (Issuer, error) {
	path := "/certificates/contacts"

	bundle := Issuer{}

	err := c.Conn.Call(ctx, conn.Put, path, nil, issuer, &bundle)
	return bundle, err
}

// UpdateCert updates the specified attributes associated with the given certificate.
func (c *Client) UpdateCert(ctx context.Context, name, version string, attr Attributes, pol Policy, tags map[string]string) (Bundle, error) {
	path := fmt.Sprintf("/certificates/%s/%s", name, version)

	bundle := Bundle{}

	body := struct {
		Attributes Attributes        `json:"attributes"`
		Policy     Policy            `json:"policy"`
		Tags       map[string]string `json:"tags"`
	}{
		Attributes: attr,
		Policy:     pol,
		Tags:       tags,
	}

	err := c.Conn.Call(ctx, conn.Patch, path, nil, body, &bundle)
	return bundle, err
}

// UpdateIssuer updates the issuer.
func (c *Client) UpdateIssuer(ctx context.Context, name string, issuer Issuer) (Issuer, error) {
	path := fmt.Sprintf("/certificates/issuers/%s", name)

	bundle := Issuer{}

	err := c.Conn.Call(ctx, conn.Patch, path, nil, issuer, &bundle)
	return bundle, err
}

// jdoak: This is something that must be for the portal or something. Basically, you want to change
// a certificate operation that is in progress. Unless someone contacts us with a need for this,
// I'm going to leave this as a placeholder as to why its not implemented.
/*
func (c *Client) UpdateOperation(ctx context.Context) {

}
*/

// UpdatePolicy updates the policy for a certificate.
func (c *Client) UpdatePolicy(ctx context.Context, name string, pol Policy) (Policy, error) {
	path := fmt.Sprintf("/certificates/%s/policy", name)

	bundle := Policy{}

	err := c.Conn.Call(ctx, conn.Patch, path, nil, pol, &bundle)
	return bundle, err
}
