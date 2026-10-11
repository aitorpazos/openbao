<!-- SPDX-License-Identifier: MPL-2.0 -->

# Documented transit key-type compatibility

Clean-room sources: `compat/specs/pki-transit-ent/20-transit.yaml` and
`notes.md`, OpenBao's MPL source, NIST SP 800-38B (CMAC), SP 800-38A
(CBC) with PKCS#7 padding, and the existing Go `crypto/mldsa` FIPS 204
implementation. No HashiCorp Vault source was consulted.

Accepted create-key spellings:

* `aes128-cmac`, `aes192-cmac`, `aes256-cmac`: real AES-CMAC generation,
  context-based derivation, batch input, version selection, truncated tags,
  URL `mac_length` precedence, and `cmac-key` export. CMAC is a MAC, **not
  encryption**, and these keys deliberately cannot encrypt or decrypt.
* `aes128-cbc`, `aes256-cbc`: real CBC encryption/decryption with PKCS#7
  padding, random or explicit 16-byte IVs, batch encryption, and existing
  context-based key derivation. The local versioned ciphertext payload is
  base64(IV || ciphertext). The landed spec asserts response shape, not
  cross-product ciphertext interchange. CBC does **not** authenticate data;
  prefer existing AEAD key types when possible. Convergent CBC is rejected.
* `ml-dsa` with `parameter_set` `44`, `65`, or `87`: aliases the existing
  `mldsa-44`, `mldsa-65`, `mldsa-87` key models without changing their old
  API spelling. The alias and parameter set are persisted on the policy.
  Signing and verification use the existing stdlib-backed implementation.
* `hybrid` with `parameter_set` `44`, `65`, or `87`,
  `hybrid_key_type_pqc=ml-dsa`, `hybrid_key_type_ec=ecdsa-p256`:
  **configuration-only**. The documented configuration and version metadata
  are persisted; create/read include an explicit warning. The spec-required
  `supports_signing=true` describes the intended algorithm category, not
  an implemented combined signer. No fake public keys or single-algorithm
  signatures are emitted. Combined signing/verification remain unsupported;
  the landed contract does not specify a combined signature encoding and
  no combined key implementation exists in-tree.

SLH-DSA is deferred. Searches for `slhdsa`, `slh-dsa`, and `sphincs` across
`sdk/` and `internal/` found no implementation to build on. No half signer or
success-shaped stub was added. Consequently `slhdsa-create` fails with 400
and `slhdsa-read` is dependency-skipped in the landed conformance suite.

Not claimed by this change: full CMAC verify API support, CMAC/CBC key import,
CBC encrypt-time key upsert, other hybrid classical algorithms, combined
hybrid signatures, or cross-product ciphertext/signature interchange. These
are outside the landed executable cases. Existing functionality is preserved.
