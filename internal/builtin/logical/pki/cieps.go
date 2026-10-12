// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

// Package pki implements the Certificate Issuance External Policy Service
// (CIEPS) Enterprise protocol as documented at
// https://developer.hashicorp.com/vault/docs/secrets/pki/cieps (v2.x latest).
// The protocol is a REST webhook: Vault POSTs a versioned JSON request to the
// configured external policy service, which responds with either a PEM
// certificate to be (re-)signed by the requested issuer, or an error.
package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ciepsRequestVersion is the current CIEPS request/response version Vault
// emits; a compatible response format is expected.
const ciepsRequestVersion = 1

// ciepsRequest is the JSON body Vault POSTs to the external policy service.
type ciepsRequest struct {
	RequestVersion           int                    `json:"request_version"`
	RequestUUID              string                 `json:"request_uuid"`
	Synchronous              bool                   `json:"synchronous"`
	UserRequestKeyValues     map[string]interface{} `json:"user_request_key_values"`
	IdentityRequestKeyValues map[string]interface{} `json:"identity_request_key_values,omitempty"`
	VaultRequestKeyValues    map[string]interface{} `json:"vault_request_key_values"`
}

// ciepsResponse is the JSON body returned by the external policy service.
// Only one of Error or Certificate should be specified; when both are
// present the error is appended to the returned warnings and the
// certificate is issued.
type ciepsResponse struct {
	RequestUUID      string   `json:"request_uuid"`
	Error            string   `json:"error,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Certificate      string   `json:"certificate,omitempty"`
	IssuerRef        string   `json:"issuer_ref"`
	StoreCertificate bool     `json:"store_certificate,omitempty"`
	GenerateLease    bool     `json:"generate_lease,omitempty"`
}

// externalPolicyConfig mirrors the storage-backed CIEPS configuration written
// by pathExternalPolicyConfig.
type externalPolicyConfig struct {
	Enabled                    bool   `json:"enabled"`
	ExternalServiceURL         string `json:"external_service_url"`
	Timeout                    int    `json:"timeout"`
	TrustedCA                  string `json:"trusted_ca"`
	TrustedLeafCertBundle      string `json:"trusted_leaf_certificate_bundle"`
	VaultClientCertBundle      string `json:"vault_client_cert_bundle"`
	EntityJMESPath             string `json:"entity_jmespath"`
	GroupJMESPath              string `json:"group_jmespath"`
	ExternalServiceLastUpdated string `json:"external_service_last_updated"`
	ExternalServiceValidated   bool   `json:"external_service_validated"`
	LastSuccessfulRequest      string `json:"last_successful_request"`
}

func getExternalPolicyConfig(ctx context.Context, s logical.Storage) (*externalPolicyConfig, error) {
	entry, err := s.Get(ctx, "config/external-policy")
	if err != nil {
		return nil, err
	}
	cfg := &externalPolicyConfig{Timeout: 15}
	if entry != nil {
		if err := entry.DecodeJSON(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// ciepsClient builds an HTTP client honouring the documented trust
// configuration: a trusted CA bundle, or a pinned leaf certificate bundle,
// optionally with a client certificate for mutual TLS.
func (cfg *externalPolicyConfig) ciepsClient() (*http.Client, error) {
	if cfg.Timeout <= 0 {
		return nil, errutil.InternalError{Err: "invalid external policy timeout"}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.TrustedCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.TrustedCA)) {
			return nil, errutil.UserError{Err: "invalid trusted_ca certificate bundle"}
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.TrustedLeafCertBundle != "" {
		pinned := x509.NewCertPool()
		if !pinned.AppendCertsFromPEM([]byte(cfg.TrustedLeafCertBundle)) {
			return nil, errutil.UserError{Err: "invalid trusted_leaf_certificate_bundle"}
		}
		leafCerts := parseCertsFromPEMBundle(cfg.TrustedLeafCertBundle)
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("external policy service presented no certificate")
			}
			presented, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("external policy service presented invalid certificate: %w", err)
			}
			// The pinned bundle must contain the exact leaf presented.
			for _, expected := range leafCerts {
				if bytes.Equal(expected.Raw, presented.Raw) {
					return nil
				}
			}
			return errors.New("external policy service certificate does not match the pinned leaf bundle")
		}
	}

	if cfg.VaultClientCertBundle != "" {
		clientCert, err := tls.X509KeyPair(extractFirstCertPEM(cfg.VaultClientCertBundle), extractFirstKeyPEM(cfg.VaultClientCertBundle))
		if err != nil {
			return nil, errutil.UserError{Err: fmt.Sprintf("invalid vault_client_cert_bundle: %v", err)}
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// parseCertsFromPEMBundle returns all parsed certificates in a PEM bundle.
func parseCertsFromPEMBundle(bundle string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// extractFirstCertPEM pulls the first CERTIFICATE PEM block out of a bundle.
func extractFirstCertPEM(bundle string) []byte {
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return pem.EncodeToMemory(block)
		}
	}
	return nil
}

// extractFirstKeyPEM pulls the first private key PEM block out of a bundle.
func extractFirstKeyPEM(bundle string) []byte {
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" || block.Type == "ENCRYPTED PRIVATE KEY" {
			return pem.EncodeToMemory(block)
		}
	}
	return nil
}

// postCIEPSRequest performs the documented webhook call: POST JSON, expect
// a 200 OK with a JSON body. Redirects are not followed (the default client
// behaviour in Go follows them; this implementation disables it as the
// documented protocol treats non-200 responses as opaque failures).
func (b *backend) postCIEPSRequest(cfg *externalPolicyConfig, req *ciepsRequest) (*ciepsResponse, error) {
	client, err := cfg.ciepsClient()
	if err != nil {
		return nil, err
	}
	// Redirects are not followed per the CIEPS documentation.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to marshal CIEPS request: %v", err)}
	}

	httpReq, err := http.NewRequest(http.MethodPost, cfg.ExternalServiceURL, bytes.NewReader(body))
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to build CIEPS request: %v", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		// When the CIEPS service is unavailable (misconfiguration or
		// outage), Vault rejects the request and the client retries.
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to contact the external policy service: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Any verbatim message returned by a non-200 status code is not
		// returned to the user; only the status is surfaced.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, errutil.InternalError{Err: fmt.Sprintf("the external policy service returned status code %d", resp.StatusCode)}
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to read the external policy service response: %v", err)}
	}

	var ciepsResp ciepsResponse
	if err := json.Unmarshal(respBody, &ciepsResp); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to parse the external policy service response: %v", err)}
	}

	if ciepsResp.RequestUUID == "" || ciepsResp.RequestUUID != req.RequestUUID {
		return nil, errutil.InternalError{Err: "the external policy service response did not echo the request UUID"}
	}

	return &ciepsResp, nil
}

// newCIEPSUUID generates the request UUID sent to and echoed by the service.
func newCIEPSUUID() (string, error) {
	return uuid.GenerateUUID()
}

// Resigning machinery: the CIEPS service returns a fully-formed PEM
// certificate whose signature is ignored; Vault extracts the TBS structure,
// replaces AIA and Authority Key Identifier information with the signing
// issuer's values (as mandated by RFC 5280), and re-signs it. These ASN.1
// structures mirror RFC 5280's TBSCertificate.

type ciepsCertificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkixAlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type ciepsTBSCertificate struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	SerialNumber   *big.Int
	Signature      pkixAlgorithmIdentifier
	Issuer         asn1.RawValue
	Validity       ciepsValidity
	Subject        asn1.RawValue
	PublicKey      ciepsPublicKeyInfo
	Extensions     []ciepsExtension `asn1:"optional,explicit,tag:3"`
}

type ciepsValidity struct {
	NotBefore, NotAfter time.Time `asn1:"utc"`
}

type ciepsPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

type ciepsExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type ciepsAuthKeyId struct {
	Ski []byte `asn1:"tag:0,optional"`
}

// OIDs used in TBS rewriting.
var (
	oidAuthorityInformationAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidCRLDistributionPoints      = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidAuthorityKeyIdentifier     = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidAccessMethodOCSP           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAccessMethodCAIssuers      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

type ciepsAccessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue `asn1:"tag:6"`
}

// ciepsReplaceAIAAndAKI rewrites AIA URIs, CRL distribution points and the
// Authority Key Identifier extension inside the given TBS bytes, returning
// the re-marshaled TBS. When the issuer has no AIA information and no
// global URLs are configured, existing AIA/CRL DP extensions are removed.
// sigAlgID is the signing issuer's AlgorithmIdentifier; RFC 5280 requires
// the TBS's inner signature field to match the outer signatureAlgorithm,
// so it is rewritten here before the issuer signs the TBS. issuerSubjectDER
// is the signing issuer's raw subject DER; RFC 5280 requires the final
// certificate's Issuer DN to equal the signing CA's Subject DN, so the
// service's Issuer value is replaced.
func ciepsReplaceAIAAndAKI(tbsRaw []byte, urls *aiaConfigEntry, issuerSKI []byte, sigAlgID pkixAlgorithmIdentifier, issuerSubjectDER []byte) ([]byte, error) {
	var tbs ciepsTBSCertificate
	if rest, err := asn1.Unmarshal(tbsRaw, &tbs); err != nil || len(rest) != 0 {
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate TBS: %w", err)
		}
		return nil, errors.New("trailing data after certificate TBS")
	}

	var accessDescriptions []ciepsAccessDescription
	if urls != nil {
		for _, uri := range urls.IssuingCertificates {
			accessDescriptions = append(accessDescriptions, ciepsAccessDescription{
				Method:   oidAccessMethodCAIssuers,
				Location: asn1.RawValue{Tag: asn1.TagIA5String, Class: asn1.ClassContextSpecific, Bytes: []byte(uri)},
			})
		}
		for _, uri := range urls.OCSPServers {
			accessDescriptions = append(accessDescriptions, ciepsAccessDescription{
				Method:   oidAccessMethodOCSP,
				Location: asn1.RawValue{Tag: asn1.TagIA5String, Class: asn1.ClassContextSpecific, Bytes: []byte(uri)},
			})
		}
	}

	var crlDPValue []byte
	if urls != nil && len(urls.CRLDistributionPoints) > 0 {
		points := make([]asn1.RawValue, 0, len(urls.CRLDistributionPoints))
		for _, uri := range urls.CRLDistributionPoints {
			dp, err := asn1.Marshal(ciepsDistributionPoint{FullName: asn1.RawValue{
				Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true,
				Bytes: mustMarshalURI(uri),
			}})
			if err != nil {
				return nil, fmt.Errorf("failed to marshal CRL distribution point: %w", err)
			}
			points = append(points, asn1.RawValue{FullBytes: dp})
		}
		marshaled, err := asn1.Marshal(points)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CRL distribution points: %w", err)
		}
		crlDPValue = marshaled
	}

	// Rebuild the extension list: drop existing AIA, CRL DP and Authority
	// Key Identifier, then append the issuer-derived values. RFC 5280
	// requires the AKI to identify the (re-)signing issuer, so the service's
	// AKI is always replaced with the issuer's SKI (or dropped when the
	// issuer has no SKI).
	var extensions []ciepsExtension
	for _, ext := range tbs.Extensions {
		switch {
		case ext.Id.Equal(oidAuthorityInformationAccess),
			ext.Id.Equal(oidCRLDistributionPoints),
			ext.Id.Equal(oidAuthorityKeyIdentifier):
			// Replaced below (or dropped).
		default:
			extensions = append(extensions, ext)
		}
	}

	if len(accessDescriptions) > 0 {
		value, err := asn1.Marshal(accessDescriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AIA extension: %w", err)
		}
		extensions = append(extensions, ciepsExtension{
			Id:    oidAuthorityInformationAccess,
			Value: value,
		})
	}

	if crlDPValue != nil {
		extensions = append(extensions, ciepsExtension{
			Id:    oidCRLDistributionPoints,
			Value: crlDPValue,
		})
	}

	if len(issuerSKI) > 0 {
		akiValue, err := asn1.Marshal(ciepsAuthKeyId{Ski: issuerSKI})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Authority Key Identifier: %w", err)
		}
		extensions = append(extensions, ciepsExtension{
			Id:    oidAuthorityKeyIdentifier,
			Value: akiValue,
		})
	}

	tbs.Extensions = extensions
	tbs.Signature = sigAlgID
	if len(issuerSubjectDER) > 0 {
		tbs.Issuer = asn1.RawValue{FullBytes: issuerSubjectDER}
	}

	// encoding/asn1 honors a set RawContent field by emitting the original
	// bytes verbatim, silently discarding any mutations made to the other
	// fields. Clear it so the mutated struct is re-encoded from scratch;
	// unmodified RawValue/BitString fields still round-trip byte-identically
	// through their FullBytes values.
	tbs.Raw = nil
	out, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal certificate TBS: %w", err)
	}
	return out, nil
}

type ciepsDistributionPoint struct {
	FullName asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// mustMarshalURI wraps a URI in an IA5String GeneralName [6] tag.
func mustMarshalURI(uri string) []byte {
	encoded, err := asn1.MarshalWithParams(uri, "ia5")
	if err != nil {
		return nil
	}
	return encoded
}
