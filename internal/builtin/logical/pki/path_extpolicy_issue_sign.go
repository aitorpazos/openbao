// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// CIEPS issuance modes documented at
// https://developer.hashicorp.com/vault/docs/secrets/pki/cieps (v2.x latest):
// the issuance_mode value sent to the external service and the corresponding
// endpoint paths.
const (
	ciepsModeSign  = "sign"
	ciepsModeIssue = "issue"
	ciepsModeICA   = "ica"
)

// algorithmIdentifierFor returns the DER-encoded AlgorithmIdentifier that Go
// would emit for the given signature algorithm, derived by signing a tiny
// throwaway certificate with the requested algorithm and extracting the
// outer signature algorithm field. Results are cached per algorithm so the
// cost is paid once. This avoids hand-maintaining OID/parameter tables
// (notably RSA-PSS and ML-DSA encodings) and guarantees byte-exact
// compatibility with x509.CreateCertificate output.
func algorithmIdentifierFor(alg x509.SignatureAlgorithm) (pkixAlgorithmIdentifier, error) {
	switch alg {
	case x509.UnknownSignatureAlgorithm, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256:
		return pkixAlgorithmIdentifier{}, fmt.Errorf("unsupported signature algorithm %v", alg)
	}

	cached, ok := algIDCache.Load(alg)
	if ok {
		return cached.(pkixAlgorithmIdentifier), nil
	}

	// Build a throwaway self-signed certificate using the requested
	// algorithm; extract and cache its AlgorithmIdentifier. A small RSA
	// probe key works for every RSA-family algorithm (PKCS#1 v1.5 and
	// PSS alike); Ed25519 and ECDSA probe keys cover their families.
	var pub crypto.PublicKey
	var priv crypto.Signer
	switch alg {
	case x509.PureEd25519:
		priv = probeEd25519Key()
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		priv = probeECDSAKey()
	default:
		priv = probeRSAKey()
	}
	pub = priv.Public()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cieps-alg-probe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    alg,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return pkixAlgorithmIdentifier{}, err
	}
	algID, err := extractSignatureAlgorithmID(der)
	if err != nil {
		return pkixAlgorithmIdentifier{}, err
	}
	algIDCache.Store(alg, algID)
	return algID, nil
}

var (
	algIDCache   sync.Map
	probeKeys    sync.Map
)

func probeRSAKey() crypto.Signer {
	return probeKeyOnce("rsa", func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 1024)
	})
}

func probeECDSAKey() crypto.Signer {
	return probeKeyOnce("ecdsa", func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	})
}

func probeEd25519Key() crypto.Signer {
	return probeKeyOnce("ed25519", func() (crypto.Signer, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	})
}

func probeKeyOnce(name string, gen func() (crypto.Signer, error)) crypto.Signer {
	if v, ok := probeKeys.Load(name); ok {
		return v.(crypto.Signer)
	}
	key, err := gen()
	if err != nil {
		// Key generation failure for a probe key is fatal for the process;
		// fall back to generating each time.
		return panicKeyGen(name, err)
	}
	probeKeys.Store(name, key)
	return key
}

func panicKeyGen(name string, err error) crypto.Signer {
	panic(fmt.Sprintf("failed to generate %v probe key: %v", name, err))
}

// extractSignatureAlgorithmID pulls the outer SignatureAlgorithm field from a
// DER certificate.
func extractSignatureAlgorithmID(der []byte) (pkixAlgorithmIdentifier, error) {
	var cert ciepsCertificate
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return pkixAlgorithmIdentifier{}, err
	}
	if len(rest) != 0 {
		return pkixAlgorithmIdentifier{}, fmt.Errorf("trailing data in throwaway certificate")
	}
	return cert.SignatureAlgorithm, nil
}

// pathExternalPolicySign registers the CIEPS-augmented sign endpoints:
// /pki/external-policy/sign(/:policy) and
// /pki/issuer/:issuer_ref/external-policy/sign(/:policy).
func pathExternalPolicySign(b *backend) *framework.Path {
	fields := getCELIssueSignFields()
	// external-policy sign takes a CSR like sign-verbatim, plus arbitrary
	// user fields passed verbatim to the policy engine.
	return &framework.Path{
		Pattern: "external-policy/sign(?:/(?P<policy>[^/]+))?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "sign",
			OperationSuffix: "with-external-policy",
		},

		Fields:              fields,
		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathExternalPolicySign,
			},
		},
		HelpSynopsis:    "Sign a CSR, deferring validation and templating to the external policy service.",
		HelpDescription: "This endpoint signs a provided CSR, after validating and templating it via the configured external policy service.",
	}
}

// pathIssuerExternalPolicySign registers the issuer-overridden variant of
// the external-policy sign path.
func pathIssuerExternalPolicySign(b *backend) *framework.Path {
	base := pathExternalPolicySign(b)
	base.Pattern = "issuer/" + framework.GenericNameRegex("issuer_ref") + "/external-policy/sign(?:/(?P<policy>[^/]+))?$"
	base.Fields["issuer_ref"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Reference to an existing issuer, either by Vault-generated identifier, the literal string default to refer to the currently configured default issuer, or the name assigned to an issuer.`,
	}
	return base
}

// pathExternalPolicyIssue registers the CIEPS-augmented issue endpoints:
// /pki/external-policy/issue(/:policy) and
// /pki/issuer/:issuer_ref/external-policy/issue(/:policy). Vault generates
// the key material and submits the CSR to the external service.
func pathExternalPolicyIssue(b *backend) *framework.Path {
	fields := getCELIssueSignFields()
	fields["key_type"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "rsa",
		Description: `The type of key to use. "rsa", "ec", "ed25519", and "mldsa"
are the only valid values outside of the empty string; the empty string
selects rsa.`,
		AllowedValues: []any{"", "rsa", "ec", "ed25519", "mldsa"},
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "",
		},
	}
	fields["key_bits"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     0,
		Description: `The number of bits to use. Allowed values are 0 (universal default); with rsa key_type: 2048 (default), 3072, or 4096; with ec key_type: 224, 256 (default), 384, or 521; ignored with key_type=ed25519.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: 0,
		},
	}
	return &framework.Path{
		Pattern: "external-policy/issue(?:/(?P<policy>[^/]+))?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "issue",
			OperationSuffix: "with-external-policy",
		},

		Fields:              fields,
		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathExternalPolicyIssue,
			},
		},
		HelpSynopsis:    "Issue a certificate, deferring validation and templating to the external policy service.",
		HelpDescription: "This endpoint issues a certificate and private key, after validating and templating the request via the configured external policy service.",
	}
}

func pathIssuerExternalPolicyIssue(b *backend) *framework.Path {
	base := pathExternalPolicyIssue(b)
	base.Pattern = "issuer/" + framework.GenericNameRegex("issuer_ref") + "/external-policy/issue(?:/(?P<policy>[^/]+))?$"
	base.Fields["issuer_ref"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Reference to an existing issuer, either by Vault-generated identifier, the literal string default to refer to the currently configured default issuer, or the name assigned to an issuer.`,
	}
	return base
}

// pathExternalPolicySignIntermediate registers the CIEPS-augmented
// sign-intermediate endpoints.
func pathExternalPolicySignIntermediate(b *backend) *framework.Path {
	fields := getCELIssueSignFields()
	return &framework.Path{
		Pattern: "external-policy/sign-intermediate(?:/(?P<policy>[^/]+))?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "sign-intermediate",
		},

		Fields:              fields,
		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathExternalPolicySignIntermediate,
			},
		},
		HelpSynopsis:    "Sign an intermediate CA CSR, deferring validation and templating to the external policy service.",
		HelpDescription: "This endpoint signs a provided intermediate CA CSR, after validating and templating it via the configured external policy service.",
	}
}

func pathIssuerExternalPolicySignIntermediate(b *backend) *framework.Path {
	base := pathExternalPolicySignIntermediate(b)
	base.Pattern = "issuer/" + framework.GenericNameRegex("issuer_ref") + "/external-policy/sign-intermediate(?:/(?P<policy>[^/]+))?$"
	base.Fields["issuer_ref"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Reference to an existing issuer, either by Vault-generated identifier, the literal string default to refer to the currently configured default issuer, or the name assigned to an issuer.`,
	}
	return base
}

func (b *backend) pathExternalPolicySign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathExternalPolicyIssueSignCert(ctx, req, data, ciepsModeSign)
}

func (b *backend) pathExternalPolicyIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathExternalPolicyIssueSignCert(ctx, req, data, ciepsModeIssue)
}

func (b *backend) pathExternalPolicySignIntermediate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathExternalPolicyIssueSignCert(ctx, req, data, ciepsModeICA)
}

func (b *backend) pathExternalPolicyIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, mode string) (*logical.Response, error) {
	cfg, err := getExternalPolicyConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.Enabled {
		return logical.ErrorResponse("the external policy service is not enabled; configure it via pki/config/external-policy first"), nil
	}

	// Resolve the user-requested issuer: the issuer-ref path variant takes
	// precedence, else the default issuer.
	requestedIssuerRef := ""
	if issuerSchema := data.Schema["issuer_ref"]; issuerSchema != nil {
		requestedIssuerRef = data.Get("issuer_ref").(string)
	} else if rawRef, ok := data.Raw["issuer_ref"].(string); ok {
		requestedIssuerRef = rawRef
	}
	if requestedIssuerRef == "" {
		requestedIssuerRef = defaultRef
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	issuerID, err := sc.resolveIssuerReference(requestedIssuerRef)
	if err != nil {
		return logical.ErrorResponse("could not fetch the CA certificate (was one set?): %v", err), nil
	}
	issuerEntry, err := sc.fetchIssuerById(issuerID)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching issuer entry: %v", err)}
	}

	signingBundle, reqErr := sc.fetchCAInfo(requestedIssuerRef, IssuanceUsage)
	if reqErr != nil {
		switch reqErr.(type) {
		case errutil.UserError:
			return logical.ErrorResponse("could not fetch the CA certificate (was one set?): %s", reqErr), nil
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", reqErr)}
		}
	}

	// Build the CSR: for sign/ica the user provides one; for issue, Vault
	// generates key material and builds the CSR on the user's behalf.
	csrPEM := ""
	privateKeyPEM := ""
	generatedKeyType := ""
	generatedKey := false
	if mode == ciepsModeIssue {
		keyType := ciepsGetString(data, "key_type")
		if keyType == "" {
			keyType = "rsa"
		}
		keyBits, err := certutil.ValidateDefaultOrValueKeyTypeLength(keyType, ciepsGetInt(data, "key_bits"))
		if err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		csrPEM, privateKeyPEM, generatedKeyType, err = generateCIEPSCSR(data, keyType, keyBits)
		if err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		generatedKey = true
	} else {
		csrPEM = ciepsGetString(data, "csr")
		if csrPEM == "" {
			return logical.ErrorResponse(`the "csr" path parameter is required`), nil
		}
		if err := validateCIEPSCSR(csrPEM); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
	}

	// Collect the unvalidated user parameters verbatim (minus the internal
	// issuance parameters Vault consumes itself).
	userKeyValues := map[string]interface{}{}
	for k, v := range data.Raw {
		if isCIEPSInternalParameter(k) || k == "csr" {
			continue
		}
		userKeyValues[k] = v
	}
	userKeyValues["csr"] = csrPEM

	vaultKeyValues := b.buildCIEPSVaultRequestValues(ctx, req, data, mode, generatedKey, issuerEntry, signingBundle)

	requestUUID, err := newCIEPSUUID()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to generate request UUID: %v", err)}
	}

	ciepsReq := &ciepsRequest{
		RequestVersion:        ciepsRequestVersion,
		RequestUUID:           requestUUID,
		Synchronous:           true,
		UserRequestKeyValues:  userKeyValues,
		VaultRequestKeyValues: vaultKeyValues,
	}
	if req.EntityID != "" {
		ciepsReq.IdentityRequestKeyValues = map[string]interface{}{
			"entity_id": req.EntityID,
		}
	}

	resp, err := b.postCIEPSRequest(cfg, ciepsReq)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}

	var warnings []string
	if resp.Error != "" {
		if resp.Certificate == "" {
			// Error response: the request is rejected.
			return logical.ErrorResponse("%s", resp.Error), nil
		}
		// Both present: certificate is issued, error becomes a warning.
		warnings = append(warnings, resp.Error)
	}
	warnings = append(warnings, resp.Warnings...)

	// Parse the returned certificate.
	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errutil.InternalError{Err: "the external policy service returned an unparseable certificate"}
	}
	ciepsCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("the external policy service returned an invalid certificate: %v", err)}
	}

	// The service may override the requested issuer.
	signingIssuerRef := requestedIssuerRef
	if resp.IssuerRef != "" {
		signingIssuerRef = resp.IssuerRef
	}
	if signingIssuerRef != requestedIssuerRef {
		signingBundle, reqErr = sc.fetchCAInfo(signingIssuerRef, IssuanceUsage)
		if reqErr != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate referenced by the external policy service: %s", reqErr)}
		}
		signingID, serr := sc.resolveIssuerReference(signingIssuerRef)
		if serr != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error resolving issuer referenced by the external policy service: %v", serr)}
		}
		issuerEntry, err = sc.fetchIssuerById(signingID)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching issuer entry referenced by the external policy service: %v", err)}
		}
	}

	// Replace AIA and AKI with the signing issuer's values, then re-sign.
	issuerURLs, _ := issuerEntry.GetAIAURLs(sc)
	var urls *aiaConfigEntry
	if issuerURLs != nil && (len(issuerURLs.IssuingCertificates) > 0 || len(issuerURLs.CRLDistributionPoints) > 0 || len(issuerURLs.OCSPServers) > 0) {
		urls = &aiaConfigEntry{
			IssuingCertificates:        issuerURLs.IssuingCertificates,
			CRLDistributionPoints:      issuerURLs.CRLDistributionPoints,
			DeltaCRLDistributionPoints: issuerURLs.DeltaCRLDistributionPoints,
			OCSPServers:                issuerURLs.OCSPServers,
		}
	}
	if urls == nil {
		globalURLs, urlErr := getGlobalAIAURLs(ctx, req.Storage)
		if urlErr != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch AIA URL information: %v", urlErr)}
		}
		urls = &aiaConfigEntry{
			IssuingCertificates:   globalURLs.IssuingCertificates,
			CRLDistributionPoints: globalURLs.CRLDistributionPoints,
			OCSPServers:           globalURLs.OCSPServers,
		}
	}

	sigAlg, err := ciepsChooseSignatureAlgorithm(ciepsCert.SignatureAlgorithm, issuerEntry, signingBundle)
	if err != nil {
		return nil, errutil.InternalError{Err: err.Error()}
	}
	algID, err := algorithmIdentifierFor(sigAlg)
	if err != nil {
		return nil, errutil.InternalError{Err: err.Error()}
	}

	newTBS, err := ciepsReplaceAIAAndAKI(ciepsCert.RawTBSCertificate, urls, signingBundle.Certificate.SubjectKeyId, algID, signingBundle.Certificate.RawSubject)
	if err != nil {
		return nil, err
	}
	signer, ok := signingBundle.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errutil.InternalError{Err: "the issuer private key cannot be used for signing"}
	}
	signature, err := signTBSWithCIEPSOpts(signer, newTBS, sigAlg)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to sign the certificate with the issuer: %v", err)}
	}

	outCert := ciepsCertificate{
		TBSCertificate:     asn1.RawValue{FullBytes: newTBS},
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}
	certBytes, err := asn1.Marshal(outCert)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to marshal the signed certificate: %v", err)}
	}
	parsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to parse the signed certificate: %v", err)}
	}

	// Build the response bundle.
	cb := &certutil.ParsedCertBundle{
		CertificateBytes: certBytes,
		Certificate:      parsed,
		CAChain:          signingBundle.CAChain,
	}
	if mode == ciepsModeIssue {
		// ParsedCertBundle expects the DER bytes; the PEM form goes directly
		// into the response data below.
		if keyBlock, _ := pem.Decode([]byte(privateKeyPEM)); keyBlock != nil {
			cb.PrivateKeyBytes = keyBlock.Bytes
		} else {
			cb.PrivateKeyBytes = []byte(privateKeyPEM)
		}
		cb.PrivateKeyType = certutil.RSAPrivateKey
		if generatedKeyType == "ec" {
			cb.PrivateKeyType = certutil.ECPrivateKey
		} else if generatedKeyType == "ed25519" {
			cb.PrivateKeyType = certutil.Ed25519PrivateKey
		}
	}
	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error converting raw signing bundle to cert bundle: %v", err)}
	}
	bundle, err := cb.ToCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error converting raw cert bundle to cert bundle: %v", err)}
	}

	// The CIEPS path schemas do not register the format field (it is part
	// of the standard issue/sign field sets), so read it schema-aware. The
	// documented CIEPS API does not define a format parameter, so the
	// response defaults to the PEM certutil bundle shape.
	format := ciepsGetString(data, "format")
	if format == "" {
		format = "pem"
	}

	caChainGen := newCaChainOutput(cb, data)
	respData := map[string]any{
		"not_before":    int64(parsed.NotBefore.Unix()),
		"expiration":    int64(parsed.NotAfter.Unix()),
		"serial_number": bundle.SerialNumber,
	}

	switch format {
	case "pem":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = bundle.Certificate
		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.pemEncodedChain()
		}
		if mode == ciepsModeIssue {
			respData["private_key"] = privateKeyPEM
			respData["private_key_type"] = string(cb.PrivateKeyType)
		}
	case "pem_bundle":
		respData["issuing_ca"] = signingCB.Certificate
		if mode == ciepsModeIssue {
			respData["certificate"] = privateKeyPEM + "\n" + bundle.Certificate
		} else {
			respData["certificate"] = bundle.Certificate
		}
		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.pemEncodedChain()
		}
	case "der":
		respData["certificate"] = base64.StdEncoding.EncodeToString(certBytes)
		respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)
		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.derEncodedChain()
		}
		if mode == ciepsModeIssue {
			respData["private_key"] = base64.StdEncoding.EncodeToString([]byte(privateKeyPEM))
			respData["private_key_type"] = string(cb.PrivateKeyType)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	if resp.StoreCertificate {
		key := "certs/" + normalizeSerial(bundle.SerialNumber)
		certsCounted := b.certsCounted.Load()
		if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: key, Value: certBytes}); err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %w", err)
		}
		b.ifCountEnabledIncrementTotalCertificatesCount(certsCounted, key)
	}

	var logicalResp *logical.Response
	if resp.StoreCertificate && resp.GenerateLease {
		logicalResp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]any{"serial_number": bundle.SerialNumber},
		)
		logicalResp.Secret.TTL = time.Until(parsed.NotAfter)
	} else {
		logicalResp = &logical.Response{Data: respData}
	}
	logicalResp.Warnings = warnings

	return logicalResp, nil
}

// buildCIEPSVaultRequestValues assembles the documented vault_request_key_values.
func (b *backend) buildCIEPSVaultRequestValues(ctx context.Context, req *logical.Request, data *framework.FieldData, mode string, generatedKey bool, issuerEntry *issuerEntry, signingBundle *certutil.CAInfoBundle) map[string]interface{} {
	leafNotAfterBehavior := "err"
	switch signingBundle.LeafNotAfterBehavior {
	case certutil.TruncateNotAfterBehavior:
		leafNotAfterBehavior = "truncate"
	case certutil.PermitNotAfterBehavior:
		leafNotAfterBehavior = "permit"
	}

	mountTTL := ""
	mountMaxTTL := ""
	if entry, ferr := req.Storage.Get(ctx, "config/tune"); ferr == nil && entry != nil {
		var tune map[string]interface{}
		if ferr = entry.DecodeJSON(&tune); ferr == nil {
			if v, ok := tune["default_lease_ttl"].(string); ok {
				mountTTL = v
			}
			if v, ok := tune["max_lease_ttl"].(string); ok {
				mountMaxTTL = v
			}
		}
	}

	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signingBundle.CertificateBytes})

	vaultKeyValues := map[string]interface{}{
		"policy_name":                 ciepsGetString(data, "policy"),
		"mount":                       strings.TrimSuffix(req.MountPoint, "/"),
		"issuance_mode":               mode,
		"vault_generated_private_key": generatedKey,
		"requested_issuer_name":       issuerEntry.Name,
		"requested_issuer_id":         issuerEntry.ID.String(),
		"requested_issuer_cert":       string(issuerPEM),
		"requested_issuance_config": map[string]interface{}{
			"leaf_not_after_behavior": leafNotAfterBehavior,
			"mount_default_ttl":       mountTTL,
			"mount_max_ttl":           mountMaxTTL,
		},
	}

	if ns, nsErr := namespace.FromContext(ctx); nsErr == nil && ns != nil {
		vaultKeyValues["namespace"] = ns.Path
	}

	return vaultKeyValues
}

// isCIEPSInternalParameter reports whether a request field is consumed by
// Vault itself and must not be forwarded verbatim to the policy service.
func isCIEPSInternalParameter(name string) bool {
	switch name {
	case "issuer_ref", "format", "key_type", "key_bits", "private_key_format",
		"pkcs12_password", "jks_password", "jks_private_key_alias",
		"remove_roots_from_chain":
		return true
	}
	return false
}

func validateCIEPSCSR(csrPEM string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid CSR format")
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		return fmt.Errorf("invalid CSR: %v", err)
	}
	return nil
}

// generateCIEPSCSR generates key material and a CSR from the user-supplied
// identity fields, returning the PEM-encoded CSR and private key.
func generateCIEPSCSR(data *framework.FieldData, keyType string, keyBits int) (string, string, string, error) {
	bundle := &certutil.ParsedCSRBundle{}
	if err := certutil.GeneratePrivateKeyWithRandomSource(keyType, keyBits, bundle, rand.Reader); err != nil {
		return "", "", "", fmt.Errorf("failed to generate key material: %v", err)
	}

	req := &x509.CertificateRequest{}
	if cn := ciepsGetString(data, "common_name"); cn != "" {
		req.Subject.CommonName = cn
	}
	req.Subject.Organization = splitCommaStrings(data, "organization")
	req.Subject.OrganizationalUnit = splitCommaStrings(data, "ou")
	req.DNSNames = splitCommaStrings(data, "alt_names")
	req.IPAddresses = parseIPsList(splitCommaStrings(data, "ip_sans"))
	for _, u := range splitCommaStrings(data, "uri_sans") {
		parsed, err := url.Parse(u)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid uri_sans value: %v", u)
		}
		req.URIs = append(req.URIs, parsed)
	}

	var csrDER []byte
	var err error
	if ecdsaKey, ok := bundle.PrivateKey.(*ecdsa.PrivateKey); ok {
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, req, ecdsaKey)
	} else if rsaKey, ok := bundle.PrivateKey.(*rsa.PrivateKey); ok {
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, req, rsaKey)
	} else if edKey, ok := bundle.PrivateKey.(ed25519.PrivateKey); ok {
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, req, edKey)
	} else if signer, ok := bundle.PrivateKey.(crypto.Signer); ok {
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, req, signer)
	} else {
		return "", "", "", fmt.Errorf("unsupported generated key type: %v", bundle.PrivateKeyType)
	}
	if err != nil {
		return "", "", "", fmt.Errorf("failed to build CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	// Match the standard issuance PEM block type per key family: PKCS#1 for
	// RSA, SEC1 for EC, PKCS#8 for ed25519.
	blockType := "RSA PRIVATE KEY"
	switch bundle.PrivateKeyType {
	case certutil.ECPrivateKey:
		blockType = "EC PRIVATE KEY"
	case certutil.Ed25519PrivateKey, certutil.MLDSAPrivateKey:
		blockType = "PRIVATE KEY"
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: bundle.PrivateKeyBytes})
	resolvedKeyType := keyType
	switch bundle.PrivateKeyType {
	case certutil.ECPrivateKey:
		resolvedKeyType = "ec"
	case certutil.Ed25519PrivateKey:
		resolvedKeyType = "ed25519"
	case certutil.MLDSAPrivateKey:
		resolvedKeyType = "mldsa"
	}
	return string(csrPEM), string(keyPEM), resolvedKeyType, nil
}

func splitCommaStrings(data *framework.FieldData, field string) []string {
	raw := ciepsGetString(data, field)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseIPsList(values []string) []net.IP {
	// The external service is responsible for validating the request; skip
	// unparseable entries rather than failing the whole request.
	var out []net.IP
	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// ciepsChooseSignatureAlgorithm picks the signature algorithm used to sign
// the policy-provided certificate: the certificate's requested algorithm
// when compatible with the issuer's key, else the default algorithm for the
// issuer's key type (per the CIEPS documentation).
func ciepsChooseSignatureAlgorithm(requested x509.SignatureAlgorithm, issuer *issuerEntry, signingBundle *certutil.CAInfoBundle) (x509.SignatureAlgorithm, error) {
	if requested != x509.UnknownSignatureAlgorithm {
		if err := issuer.CanMaybeSignWithAlgo(requested); err == nil {
			return requested, nil
		}
	}

	switch signingBundle.Certificate.PublicKeyAlgorithm {
	case x509.RSA:
		return x509.SHA256WithRSA, nil
	case x509.ECDSA:
		return x509.ECDSAWithSHA256, nil
	case x509.Ed25519:
		return x509.PureEd25519, nil
	default:
		// ML-DSA issuers: match the issuer parameter set to the
		// corresponding signature algorithm.
		switch signingBundle.Certificate.SignatureAlgorithm {
		case x509.MLDSA44:
			return x509.MLDSA44, nil
		case x509.MLDSA65:
			return x509.MLDSA65, nil
		case x509.MLDSA87:
			return x509.MLDSA87, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported issuer key type for CIEPS signing: %v", signingBundle.Certificate.PublicKeyAlgorithm)
}

// signTBSWithCIEPSOpts signs the raw TBS bytes the same way
// x509.CreateCertificate would: hashing per the signature algorithm (RSA),
// using PSS options with salt length equal to the hash size, and passing
// no hash for Ed25519/ML-DSA signers.
func signTBSWithCIEPSOpts(signer crypto.Signer, tbs []byte, sigAlg x509.SignatureAlgorithm) ([]byte, error) {
	var signerOpts crypto.SignerOpts
	switch sigAlg {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		signerOpts = crypto.SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		signerOpts = crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		signerOpts = crypto.SHA512
	default:
		signerOpts = crypto.Hash(0)
	}

	if isCIEPSSPSSAlgorithm(sigAlg) {
		hashFunc, ok := signerOpts.(crypto.Hash)
		if !ok {
			return nil, fmt.Errorf("PSS signature algorithm requires a hash function")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		}
	}

	return crypto.SignMessage(signer, rand.Reader, tbs, signerOpts)
}

func isCIEPSSPSSAlgorithm(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	}
	return false
}

// ciepsGetString reads a string field that may not be registered in every
// path's schema (the arbitrary-input CIEPS paths accept fields from multiple
// families).
func ciepsGetString(data *framework.FieldData, key string) string {
	if data.Schema[key] == nil {
		if raw, ok := data.Raw[key].(string); ok {
			return raw
		}
		return ""
	}
	return data.Get(key).(string)
}

// ciepsGetInt reads an integer field that may not be registered in every
// path's schema.
func ciepsGetInt(data *framework.FieldData, key string) int {
	if data.Schema[key] == nil {
		if raw, ok := data.Raw[key].(int); ok {
			return raw
		}
		return 0
	}
	return data.Get(key).(int)
}
