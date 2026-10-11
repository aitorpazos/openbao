<!-- SPDX-License-Identifier: MPL-2.0 -->

# Local LDAP configuration backend

Clean-room sources: the landed `compat/specs/plugin-rotation-seal/10-provider-rotation.yaml`
and `notes.md`, OpenBao SDK helpers, and public Vault v2.x (latest) API documentation:

- https://developer.hashicorp.com/vault/api-docs/auth/ldap
- https://developer.hashicorp.com/vault/api-docs/secret/ldap

No Vault implementation source was consulted.

`Factory` is a credential backend: config, users, groups, and explicitly rejected
login/root-rotation operations. The documented auth API has **no `role/:name`
endpoint**. User/group policy associations are not LDAP account provisioning.
Token settings belong to auth config, not fictitious auth roles.

`SecretsFactory` is a logical backend, provided in this package to keep this change
within its assigned lane. It exposes config, static-role CRUD/list, empty-mount
static-migration status/start/stop, and explicitly rejected rotation operations.
The landed spec deliberately places self-managed config, static roles and migration
under a **secrets mount**, not an auth mount. Both factories need independent registry
entries to run all LDAP spec cases.

This is **configuration-only**, not a working LDAP authentication or rotation
provider. It never opens a connection to LDAP. Config/static-role writes return an
explicit limitation warning; `verify_connection=true` is rejected before storage.
An omitted verification flag permits local config writes (as required by the landed
LDAP fixtures); `verify_connection=false` explicitly permits the same offline path.
Schedules and rotation-policy names are stored, not executed. Policy names are not
resolved by this backend. A static role can only be created when import rotation is
skipped, using the role flag or the config default. Passwords and TLS private keys
are not returned from config/role reads; their storage paths are seal-wrapped.

On an empty secrets mount migration is a no-op, with `include_role_names` required
for status. Nonempty migration is rejected rather than fabricating successful
migration state. Dynamic secrets provisioning, live login, password verification,
password rotation, background scheduling, and actual legacy-role migration are not
implemented. Use an operational LDAP plugin when those capabilities are needed.

Registry integration (not changed by this package):

```go
credLdap "github.com/openbao/openbao/v2/internal/builtin/credential/ldap"
// credentialBackends:
"ldap": {Factory: credLdap.Factory},
// logicalBackends:
"ldap": {Factory: credLdap.SecretsFactory},
```
