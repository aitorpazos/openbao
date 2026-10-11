<!-- Copyright (c) OpenBao Contributors -->
<!-- SPDX-License-Identifier: MPL-2.0 -->

# Native KMIP pass D: supported subset and deviations

This is a clean-room implementation based on the public [OASIS KMIP 1.4
specification](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html),
not Vault implementation source. It is not a claim of full KMIP conformance.
The HTTP-only compatibility harness is deliberately unchanged.

## Wire format

* Section 9.1 (TTLV encoding), especially 9.1.3.1 (tags), 9.1.3.2
  (enumerations): big-endian headers, eight-byte alignment, zero padding,
  nested structures, all ten KMIP 1.4 primitive/structure types. Big integers
  are signed two's-complement byte arrays in multiples of eight bytes.
* **Structure is 0x01**, not 0x0C. 0x0C is not accepted as a structure type.
  Opaque Object is an object structure containing Opaque Data Type and Opaque
  Data Value (section 2.2.8); Archive Date is a Date-Time attribute (3.32).
  Neither is a separate TTLV primitive type.
* KMIP **1.4 and 2.0** are accepted; responses echo the supported request
  version. This remains a deliberately limited subset, not full conformance.
  Version-specific attribute structures are described below.
* Limits: four MiB per frame, nesting depth 32, 128 concurrent connections,
  15-second handshake and 30-second per-request I/O deadline. Invalid framing
  closes the connection. Multiple synchronous batch items are processed in
  request order (sections 6.4, 6.12–6.15, 7.1–7.2), with independent results and
  supplied Unique Batch Item IDs echoed, including failures. Continue (wire 1)
  processes later items after failure; Stop (2) ends at the failing item and
  returns only processed items with the corresponding response Batch Count.
  Undo (3), unknown options, true Asynchronous Indicator, and Maximum Response
  Size are rejected before any operation executes (existing reason 4 convention).
  False asynchronous and either Batch Order Option value are accepted; execution
  remains sequential. Extensions, placeholders and batch dependencies remain
  unsupported. **Local compatibility deviations:** omitted continuation defaults
  to Continue as requested for this subset, whereas section 6.13 specifies Stop;
  section 9.1.3.2.30 calls value 1 Continue, not PROCESS, and defines no IGNORE.
  Missing multi-item IDs are tolerated; supplied IDs must be unique ByteStrings
  (the spec requires IDs for multi-item requests).

## Operations and objects

Operations use section 4 request/response definitions and sections 6–7 message
headers, batch items and result status/reason fields.

* Discover Versions: 2.0 then 1.4 (server preference); intersects supplied
  version lists, without duplicates. An empty intersection is an empty payload.
* Query: Query Operations, Query Objects, Query Server Information (vendor
  identifier); 2.0 also adds Defaults Information and Storage Protection Masks
  below. Other query functions return an unsupported-operation result.
* Create: AES Symmetric Key only (128/192/256 bits), raw Key Block/Key Value/
  Key Material (sections 2.1.3–2.1.5, 2.2.2). Algorithm and length are required
  Template-Attribute entries. Cryptographic Usage Mask is stored when supplied;
  defaults to zero. Other attributes and object types are rejected by Create.
  Register and Create Key Pair support the additional objects described below;
  Secret Data remains deferred.
* Get: raw AES ByteString inside the standard Symmetric Key / Key Block /
  Key Value / Key Material structure, not an untyped standalone byte response.
  Get without wrapping preserves its original wire representation. Wrapped Get
  (section **4.11**, not 4.4) accepts **Key Wrapping Specification** (2.1.6) in
  requests, not Key Wrapping Data, which belongs in responses (2.1.5). The slice
  is Encrypt (Wrapping Method 1), explicit NISTKeyWrap (Block Cipher Mode 0x0D,
  9.1.3.2.14), and explicit No Encoding (Encoding Option 1). Omitted encoding
  means TTLV in the spec and is rejected, not silently treated as raw. AES-KW
  follows RFC 3394 with the default integrity register and no padding, for
  128/192/256-bit target and wrapping keys. The wrapping key must be a different
  AES object in the authenticated role's store, Active, with Wrap Key usage
  (0x10); missing, inactive, and unauthorized keys return reasons 1, 11, and 12.
  Wrapped Key Value is a ByteString; Key Wrapping Data records the method,
  Encryption Key Information (identifier and Cryptographic Parameters), and
  encoding. Unknown/duplicate wrapping fields and other methods, modes, or
  encodings return reason 5 (unsupported operation parameter convention);
  same-key wrapping and invalid material return reason 4.
  **Parameter-model deviation:** this subset has no stored Cryptographic
  Parameters attribute; it accepts explicit AES/NISTKeyWrap parameters without
  the stored-attribute match required by section 2.1.6. It does not infer missing
  parameters or implement general attribute mutation. Alternate formats,
  compression, and sensitive/nonextractable policies remain unsupported.
* Get Attributes/Get Attribute List: Unique Identifier, Object Type,
  Cryptographic Algorithm, Cryptographic Length, Cryptographic Usage Mask,
  State, and Activation Date when set (section 3). Attribute selection is by
  name in 1.4, by Attribute Reference in 2.0. Certificate Type/Length,
  Cryptographic Domain Parameters (EC), and Link are returned where applicable.
  Private/Public Key Unique Identifier are Create Key Pair response fields;
  the actual reciprocal object attributes are Link, per the specification.
* Locate: exact State, Object Type and Cryptographic Algorithm filters, ANDed;
  unfiltered requests list role-local objects. Pagination, date comparisons,
  names and storage-status filters are unsupported. Limit: 4096 stored objects
  per Locate enumeration; destroyed tombstones remain visible.
* Activate: Pre-Active (state 1, the spec's term for a newly created object)
  to Active (2), recording Activation Date. Other transitions are rejected.
* Destroy: Pre-Active to Destroyed (5), removing material but retaining metadata.
  Active-key destruction is prohibited by the state model; Revoke/deactivation
  is deferred. Consequently active keys cannot be destroyed in this subset.
  Physical erasure of earlier storage snapshots is not claimed.
* Re-key: new random AES material and identifier, copied algorithm/length/usage,
  Pre-Active state; old object unchanged. Activation offset, links, historical
  attributes and template overrides are deferred.
* Sign: single-part Data ByteString; identifier MUST be the authenticated
  credential's serial. ECDSA ASN.1 or RSA-PSS with SHA-256 (PSS salt = hash size),
  selected by the role's credential key type. Explicit Cryptographic Parameters,
  prehashed data and multipart signatures are rejected. This credential-as-key
  convention is a local subset, not a complete private-key KMIP object model.

## Pass D: versions, attributes, certificates, and key pairs

### Public specification provenance and corrected references

Only the existing clean-room implementation and public OASIS documents were
consulted. No HashiCorp/Vault source was accessed; no git commands were used.
The supplied `.../kmip/spec/v2.0/os/...` URL returned HTTP 404. The published
[KMIP 2.0 OS specification](https://docs.oasis-open.org/kmip/kmip-spec/v2.0/os/kmip-spec-v2.0-os.html)
and the 1.4 URL above were fetched over HTTPS.

* **2.0 §§5.1–5.5** define Attributes, Common Attributes, Private Key
  Attributes, Public Key Attributes, and Attribute Reference. Attributes contain
  directly tagged values, **not** nested name/value wrappers. References to
  standard attributes are Enumerations whose values are the attribute tags.
* **2.0 §§6.1.16, 9.16** define Discover Versions and protocol version fields;
  versions are ranked by preference, not mandated numerical order. We prefer
  2.0. **1.4 §4.26** defines the corresponding legacy discovery operation.
  Unsupported header versions fail before side effects; a 2.0 client can
  discover 1.4 and subsequently issue 1.4 requests. No automatic rewriting of
  legacy 1.4 request bodies under a 2.0 header is performed.
* **2.0 §§6.1.20–6.1.21, 6.1.27** define Get Attributes, Get Attribute List,
  and Locate. The supported 1.4 operations use the new attribute containers and
  references when requested under 2.0. Legacy wrappers under 2.0 are rejected.
* **2.0 §§6.1.37, 7.7, 7.18, 7.27, 11.43** define Query and its information
  structures/enumerations. There is no "Query Attributes" function. Query
  Defaults Information (13) returns Object Defaults / Attributes / Usage Mask
  zero for supported object types. Query Storage Protection Masks (14) returns
  an empty Protection Storage Masks structure, explicitly permitted by Query.
  Existing Query Operations/Objects/Server Information remain supported.
* **2.0 §§11.12, 11.25, 11.28, 11.44, 11.54** supply algorithm, key format,
  link, curve, and tag enumerations. Only needed tags were added.
* **1.4 §§2.2.1, 2.2.3, 2.2.4** (not 2.1.2/2.1.6/2.1.7) define Certificate,
  Public Key, Private Key; **§§2.1.3–2.1.4** define Key Block/Key Value.
  **§4.2** (not 4.6) is Create Key Pair; **§4.3** (not 4.24) is Register.
  **§§3.7–3.9, 3.35** define domain parameters, certificate metadata, and Link.
  Corresponding 2.0 operations are **§§6.1.9 and 6.1.39**.

### Implemented factory operations

* Register accepts X.509 Certificate objects with Certificate Type 1. DER is
  parsed and preserved byte-for-byte. As a **local input extension**, a single
  PEM CERTIFICATE block is also accepted and preserved byte-for-byte on Get;
  standard KMIP X.509 Certificate Value is DER. Certificate Length describes
  decoded DER length. Concatenated PEM and malformed certificates are rejected.
* Public keys accept DER X.509 SubjectPublicKeyInfo (Key Format Type 5);
  private keys accept DER PKCS#1 (3), PKCS#8 (4), ECPrivateKey (6). Material is
  parsed, RSA private keys validated, and supplied algorithm/length checked
  against material. Wrapped, encrypted, transparent, opaque and PEM key formats
  are rejected. RSA and NIST EC keys only, with the sizes listed below.
* Create Key Pair generates RSA 2048/3072/4096 or EC/ECDSA P-256/P-384/P-521,
  using crypto/rand. Algorithm and length are attributes; curve is Recommended
  Curve inside Cryptographic Domain Parameters (not Cryptographic Parameters).
  Algorithm-only Cryptographic Parameters is accepted; other parameters fail.
  EC length may be derived from an explicit curve, or curve from explicit length.
  No default algorithm or size is selected. Common attributes are overlaid by
  per-half attributes; algorithm/length/curve must agree, usage masks may differ.
  Generated private keys use PKCS#8; public keys use X.509 SPKI.
* Each half has a fresh role-local identifier and independent state. Reciprocal
  Link attributes use Public Key Link 0x102 / Private Key Link 0x103. The response
  contains Private Key Unique Identifier and Public Key Unique Identifier; these
  response fields are **not invented as object attributes**. Storage writes are
  serialized with other operations. A failed second write attempts deletion of
  the first; the logical store provides no two-entry crash-atomic transaction.
* Existing AES entries have a zero discriminator and remain readable without
  migration. New object types participate in Get, attributes, Locate, Activate,
  and Destroy. This subset uses the same Pre-Active → Active / Pre-Active →
  Destroyed lifecycle for registered objects, retaining destroyed metadata and
  removing material. AES wrapping and Re-key are not extended to these objects.
* Role permissions use the pre-existing HTTP names `operation_register` and
  `operation_create_keypair`. Private-key objects are retained for future use;
  **Sign is unchanged**, and still requires the authenticated credential serial
  and its retained signing key. No fallback to arbitrary private-key objects is
  attempted when a credential has no signing key.

### Deliberate subset choices and deferred structures

Factory usage defaults to zero (including Register), and absent/empty legacy
Template-Attribute is tolerated. Register derives key algorithm/length and
certificate length instead of requiring every client-supplied field specified
by §6.1.39. Full mandatory attribute bookkeeping (Initial Date, Last Change Date,
Digital Signature Algorithm, certificate identifiers/issuer/subject), general
Cryptographic Parameters, custom/vendor attributes, multi-instance attribute
indices, attribute mutation, sensitivity/extractability policy, and protection
storage selections are deferred. The new containers do not imply support for
these attributes; unsupported inputs are rejected. Enumerated/integer Unique
Identifiers and ID Placeholders remain unsupported. Therefore a Register/Get
batch test uses a previously registered identifier for Get, not an implied
dependency on the preceding Register. Certificates are parsed, not validated
against a trust chain. Private-key entries are not HTTP credential entries.

Pass D tests exercise both wire versions (TTLV encode/decode), ordered discovery
and down-negotiation, new attribute references and defaults Query, certificate
DER/PEM preservation, all six RSA/EC size choices, reciprocal Links, independent
usage masks, key parsing and matching halves, Register round trips, object-type
Locate across AES/certificate/public/private objects, registered object state
transitions and material removal, Register/Get batches, malformed inputs, and
factory authorization. The TLS discovery test now expects both versions; all
previous signing, wrapping, batching, TLS, and HTTP regression tests remain.

## Credentials, storage, and TLS

TLS 1.2+ with RequireAndVerifyClientCert, named listener CA and optional additional
named client CAs. A separate server-auth leaf with configured DNS/IP SANs is
issued by the named CA at each handshake, avoiding use of the CA certificate as
an endpoint leaf and avoiding expired startup leaves on long-lived mounts.
The configured TLS min/max versions are honored. Custom cipher suite lists and
legacy-CA selection are rejected rather than silently ignored. Imported CAs
can provide client trust, but cannot issue server leaves.

Pass A certificates use **CN = role**, **OU = scope**, and serial = credential
identifier; there is no separate credential-name field. Authorization preserves
that existing format and requires exact DER equality with the stored credential,
not merely a trusted issuer or a matching CN. Roles, operation permissions,
credential expiry and revocation are checked on every request, including an
already-established connection. Objects live under the role's storage prefix;
identifiers cannot traverse paths or access another role's objects.

Newly generated credentials retain signing material under a separate
`credential/<serial>/signing-key` storage entry, never in publicly readable
credential metadata. The scope prefix is seal-wrap designated, and credential
revocation removes both entries. HTTP private keys are still returned only at
issuance, never lookup. **This adds key retention compared with pass A.** Existing
pass-A credentials must be reissued to use Sign; CSR-signed credentials have no
server-side private key and cannot use Sign. No existing certificate or key is
silently replaced.

## Lifecycle and operational limits

The framework InitializeFunc starts persisted listeners at mount initialization;
Cleanup closes listeners and accepted connections and waits for handlers. HTTP
requests reconcile changed listener settings, guarded by a separate mutex;
listener deletion closes sessions. Rewrites replace changed listeners. Initial
bind/TLS errors are returned to the caller, explicitly noting that the desired
configuration is already persisted. A failed replacement may leave that listener
stopped; retry or repair its configuration. Generic mount tuning that does not
change listener storage does not restart sockets. There is no core modification
or listener invalidation callback; out-of-band storage changes are reconciled on
the next successful HTTP request or backend reinitialization. Replication DR
secondaries/performance standbys do not start listeners. Full multi-node HA
failover and mount-tune orchestration are not covered by the local tests.

Tests cover codec vectors, all types, nesting/padding, malformed and bounded
frames, TLS end-to-end Discover/Create/Get/Destroy, authorization and revocation,
role isolation, attributes, Locate, state transitions, Re-key, ECDSA/RSA signing,
and concurrent lifecycle reconciliation. Pass C adds batch Continue/Stop,
per-item ID echo and failure results, rejected controls without side effects,
wrapped/plain Get stability, AES-KW known-answer and round-trip checks for all
supported key sizes, invalid wrapping controls, wrapping-key state/usage checks,
and cross-role wrapping-key isolation. Batch tests round-trip TTLV frames; the
Create/Get/Destroy batch uses an existing identifier for Get/Destroy, since ID
placeholders are not implemented. They use an in-memory logical store and
real loopback TLS with a generated self-signed CA, not simulated wire responses.
