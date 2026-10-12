// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

// ciepsmock is a stand-alone TLS server implementing the documented CIEPS
// (Certificate Issuance External Policy Service) webhook contract for
// conformance-verification purposes:
// https://developer.hashicorp.com/vault/docs/secrets/pki/cieps (v2.x latest).
//
// Behaviour:
//   - Parses the documented Vault request and echoes request_uuid.
//   - For issue-mode requests, extracts the CSR from
//     user_request_key_values.csr and copies the subject public key,
//     common name and SANs into the returned certificate.
//   - Signs the returned certificate with its own key; Vault ignores this
//     signature and re-signs the TBS with the requested issuer.
//   - Supports ?error=1 to return the documented error-only response and
//     ?both=1 to return both certificate and error (error becomes a warning).
//   - Serves a plain-HTTP status endpoint (default :8434) that reports the
//     last received request for manual verification.
//
// Usage:
//
//	ciepsmock -tls-addr 127.0.0.1:8433 -http-addr 127.0.0.1:8434 \
//	  -cert ca.pem -key leaf.key
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ciepsRequest struct {
	RequestVersion           int                    `json:"request_version"`
	RequestUUID              string                 `json:"request_uuid"`
	Synchronous              bool                   `json:"synchronous"`
	UserRequestKeyValues     map[string]interface{} `json:"user_request_key_values"`
	IdentityRequestKeyValues map[string]interface{} `json:"identity_request_key_values,omitempty"`
	VaultRequestKeyValues    map[string]interface{} `json:"vault_request_key_values"`
}

type ciepsResponse struct {
	RequestUUID      string   `json:"request_uuid"`
	Error            string   `json:"error,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Certificate      string   `json:"certificate,omitempty"`
	IssuerRef        string   `json:"issuer_ref"`
	StoreCertificate bool     `json:"store_certificate,omitempty"`
	GenerateLease    bool     `json:"generate_lease,omitempty"`
}

var (
	lastMu    sync.Mutex
	lastReq   map[string]interface{}
	issuerRef = flag.String("issuer-ref", "default", "issuer_ref value returned by the mock")
)

func main() {
	tlsAddr := flag.String("tls-addr", "127.0.0.1:8433", "CIEPS HTTPS listener")
	httpAddr := flag.String("http-addr", "127.0.0.1:8434", "status HTTP listener")
	certPath := flag.String("cert", "", "TLS leaf certificate PEM")
	keyPath := flag.String("key", "", "TLS leaf key PEM")
	flag.Parse()

	if *certPath == "" || *keyPath == "" {
		log.Fatal("both -cert and -key are required")
	}

	var err error
	signingCA, err = newMockCA()
	if err != nil {
		log.Fatalf("failed to create mock signing CA: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("failed to load TLS key pair: %v", err)
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
			lastMu.Lock()
			defer lastMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			if lastReq == nil {
				enc.Encode(map[string]any{"received": false})
				return
			}
			enc.Encode(lastReq)
		})
		if err := http.ListenAndServe(*httpAddr, mux); err != nil {
			log.Fatalf("status server: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req ciepsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		lastMu.Lock()
		lastReq, _ = anyMap(req)
		lastMu.Unlock()

		warnings := []string{}
		if req.VaultRequestKeyValues != nil {
			if mode, _ := req.VaultRequestKeyValues["issuance_mode"].(string); mode == "ica" {
				warnings = append(warnings, "mock: intermediate signing mode")
			}
		}

		q := r.URL.Query()
		if q.Get("status") != "" {
			// Non-200 status: per the documented contract Vault only
			// surfaces the status code, never the verbatim message.
			http.Error(w, "verbatim internal mock detail", http.StatusServiceUnavailable)
			return
		}
		if q.Get("error") != "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ciepsResponse{RequestUUID: req.RequestUUID, Error: "mock: policy rejected the request", IssuerRef: *issuerRef})
			return
		}
		if q.Get("nonjson") != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not json"))
			return
		}
		if q.Get("mismatch") != "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ciepsResponse{RequestUUID: "not-the-request-uuid", IssuerRef: *issuerRef})
			return
		}

		csrPEM, _ := req.UserRequestKeyValues["csr"].(string)
		block, _ := pem.Decode([]byte(csrPEM))
		var parsedCSR *x509.CertificateRequest
		if block != nil {
			parsedCSR, err = x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				parsedCSR = nil
			}
		}

		cn := "mock.cieps.local"
		if parsedCSR != nil && parsedCSR.Subject.CommonName != "" {
			cn = parsedCSR.Subject.CommonName
		}

		respCert, err := buildMockCertificate(parsedCSR, cn)
		if err != nil {
			http.Error(w, "failed to build certificate", http.StatusInternalServerError)
			return
		}

		resp := ciepsResponse{
			RequestUUID:      req.RequestUUID,
			Warnings:         warnings,
			Certificate:      respCert,
			IssuerRef:        *issuerRef,
			StoreCertificate: q.Get("store") != "",
			GenerateLease:    q.Get("lease") != "",
		}
		if q.Get("both") != "" {
			resp.Error = "mock: minor policy issue (certificate still issued)"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:      *tlsAddr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("ciepsmock listening on https://%s (status http://%s)", *tlsAddr, *httpAddr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("CIEPS server: %v", err)
	}
}

func anyMap(req ciepsRequest) (map[string]interface{}, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// mockSigningCA is the internal CA the mock uses to sign returned
// certificates. Vault ignores the signature (the documented protocol
// re-signs the TBS with the requested issuer), but x509.CreateCertificate
// requires parent/key agreement, so a proper mini-CA is used.
type mockCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newMockCA() (*mockCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CIEPS Mock Signing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &mockCA{cert: cert, key: key}, nil
}

var signingCA *mockCA

// buildMockCertificate creates a certificate whose TBS carries the CSR's
// public key and subject; the mock's own signature is ignored by Vault.
func buildMockCertificate(csr *x509.CertificateRequest, cn string) (string, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()%99999999 + 1),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"CIEPS Mock"},
			OrganizationalUnit: []string{"Conformance"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	if csr != nil {
		template.PublicKey = csr.PublicKey
		template.Subject.CommonName = cn
		template.Subject.Organization = csr.Subject.Organization
		template.Subject.OrganizationalUnit = csr.Subject.OrganizationalUnit
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
		template.URIs = csr.URIs
	}
	if cn != "" && strings.Contains(cn, "*") {
		template.DNSNames = append(template.DNSNames, cn)
	}

	// The mock's signature is ignored by Vault (the documented protocol
	// re-signs the TBS with the requested issuer), so the signing key need
	// not match the certificate's embedded public key when the CSR carries
	// one.
	der, err := x509.CreateCertificate(rand.Reader, template, signingCA.cert, template.PublicKey, signingCA.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
