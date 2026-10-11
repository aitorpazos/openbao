<!-- Copyright (c) OpenBao Contributors -->
<!-- SPDX-License-Identifier: MPL-2.0 -->

# Native KMIP pass B: supported subset and deviations

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
* The shared primitives are usable for KMIP 2.0 TTLV, but KMIP 2.0 operation
  schemas, its attribute model, and extended types are deferred. Only **1.4**
  is advertised and accepted, rather than falsely advertising 2.0 support.
* Limits: four MiB per frame, nesting depth 32, 128 concurrent connections,
  15-second handshake and 30-second per-request I/O deadline. Invalid framing
  closes the connection. Single synchronous batch items only (sections 6–7);
  asynchronous options, extensions, placeholders, batch dependencies, maximum
  response size negotiation and undo are rejected/not supported.

## Operations and objects

Operations use section 4 request/response definitions and sections 6–7 message
headers, batch items and result status/reason fields.

* Discover Versions: only 1.4; intersects supplied version lists.
* Query: Query Operations, Query Objects, Query Server Information (vendor
  identifier). Other query functions return an unsupported-operation result.
* Create: AES Symmetric Key only (128/192/256 bits), raw Key Block/Key Value/
  Key Material (sections 2.1.3–2.1.5, 2.2.2). Algorithm and length are required
  Template-Attribute entries. Cryptographic Usage Mask is stored when supplied;
  defaults to zero. Other attributes and object types are rejected. Certificate,
  Secret Data, Private Key and Create Key Pair have protocol tag/operation
  constants but generation/import and key-pair object creation are deferred.
* Get: raw AES ByteString inside the standard Symmetric Key / Key Block /
  Key Value / Key Material structure, not an untyped standalone byte response.
  Wrapping, alternate formats, compression, sensitive/nonextractable policies
  and attribute mutation are unsupported.
* Get Attributes/Get Attribute List: Unique Identifier, Object Type,
  Cryptographic Algorithm, Cryptographic Length, Cryptographic Usage Mask,
  State, and Activation Date when set (section 3). Attribute selection is by
  name. Private/Public Key Unique Identifier tags are reserved for future
  key-pair support, not returned on symmetric objects.
* Locate: exact State and Cryptographic Algorithm Attribute filters, ANDed;
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
and concurrent lifecycle reconciliation. They use an in-memory logical store and
real loopback TLS with a generated self-signed CA, not simulated wire responses.
