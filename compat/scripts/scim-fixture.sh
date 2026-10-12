#!/usr/bin/env bash
# SCIM fixture bootstrap — Vault Enterprise SCIM conformance (compat/specs/scim).
#
# Performs the operator setup documented in compat/specs/scim/notes.md on a
# disposable dev target:
#   1. activate SCIM (one-way, root-only),
#   2. create the compat-scim-policy ACL policy,
#   3. create/reuse the compat-scim-user userpass account,
#   4. mint an entity-bound token for the account,
#   5. register the compat-scim-actor SCIM client bound to that entity.
# Prints the actor token on stdout (last line) for `harness --token $(...)`.
#
# Usage: ./scim-fixture.sh <base-url> <root-token>
# Requires: python3, curl.

set -euo pipefail

BASE=${1:?base url required}
ROOT=${2:?root token required}

post() { curl -s -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $1" -X POST -d "$2" "$BASE$3"; }

# 1. Activation is one-way; tolerate an already-activated target.
code=$(post "$ROOT" '{}' /v1/sys/activation-flags/enable-scim/activate)
if [ "$code" != 204 ] && [ "$code" != 400 ]; then
  echo "unexpected activation status $code" >&2; exit 1
fi

# 2. Policy: protocol ACLs plus the fixture management reads.
python3 - <<'EOF' > /tmp/scim-policy.json
import json
print(json.dumps({"policy": '''path "identity/scim/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "identity/entity/name/compat-scim-entity" {
  capabilities = ["read"]
}
'''}))
EOF
code=$(post "$ROOT" "$(cat /tmp/scim-policy.json)" /v1/sys/policies/acl/compat-scim-policy)
if [ "$code" != 204 ] && [ "$code" != 400 ]; then
  echo "unexpected policy status $code" >&2; exit 1
fi
rm -f /tmp/scim-policy.json

# 3. userpass is mounted on dev targets; create/update the fixture user.
code=$(post "$ROOT" '{"type":"userpass"}' /v1/sys/auth/userpass)
if [ "$code" != 204 ] && [ "$code" != 400 ]; then
  echo "unexpected mount status $code" >&2; exit 1
fi
code=$(post "$ROOT" '{"password":"compat-scim-password","token_policies":"compat-scim-policy"}' /v1/auth/userpass/users/compat-scim-user)
if [ "$code" != 204 ]; then
  echo "user creation failed: $code" >&2; exit 1
fi

# 4. Mint the entity-bound token.
login=$(curl -s -X POST -d '{"password":"compat-scim-password"}' "$BASE/v1/auth/userpass/login/compat-scim-user")
token=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(d['auth']['client_token'])" "$login" 2>/dev/null || true)
entity=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(d['auth']['entity_id'])" "$login" 2>/dev/null || true)
if [ -z "${token:-}" ] || [ -z "${entity:-}" ]; then
  echo "login failed: $login" >&2; exit 1
fi

# 5. Register the SCIM client bound to the actor entity (management call).
code=$(post "$ROOT" "{\"access_grant_principal\":\"$entity\"}" /v1/identity/scim/client/compat-scim-actor)
if [ "$code" != 204 ] && [ "$code" != 400 ]; then
  echo "unexpected client status $code" >&2; exit 1
fi

echo "$token"
