# Events — subscription API

## Sources

| URL | Version label | Notes |
| --- | --- | --- |
| https://developer.hashicorp.com/vault/docs/concepts/events | v2.x (latest) | Enterprise-gated. Event-type table (all 56 documented types with metadata fields), CloudEvents JSON envelope with worked example, WebSocket subscription endpoint `/v1/sys/events/subscribe/{eventType}`, `json=true` query parameter, protobuf-by-default delivery, policy grants (read on subscribe path; list+subscribe+subscribe_event_types on secret paths), multi-node subscription semantics (active node + performance standbys; reroute via api_addr), version support table (1.16+ GA, enabled by default; 1.13/1.14 require the `events.alpha1` experiment). |
| https://developer.hashicorp.com/vault/docs/commands/events | v2.x (latest) | CLI `events subscribe` flags mirror the endpoint contract: type glob (`*` wildcard), `-namespaces` (repeated; child namespace patterns with wildcard; issuing namespace prepended; default scope is the requesting namespace only), `-filter` (filter expression; selectors `event_type`, `operation`, `source_plugin_mount`, `data_path`, `namespace`; applied after policy checks), `-timeout`. Output is JSON, one event per line ("protobuf JSON serialization format"). |
| https://developer.hashicorp.com/vault/docs/concepts/filtering | v2.x (latest) | Filter expression grammar: JSON-pointer selectors, operators `==`, `!=`, `is empty`, `is not empty`, `in`, `not in`, `contains`, `not contains`, `matches`, `not matches`; boolean `and`/`or`/`not`; grouping; standard precedence. |
| https://developer.hashicorp.com/vault/docs/plugins/plugin-development-event-notifications | v2.x (latest) | Plugin producer contract: `logical.SendEvent(ctx, backend, eventType, metadata...)`, `logical.EventSender` interface, `framework.ErrNoEvents` sentinel (events unavailable/disabled), non-blocking async delivery, plugin-name event-type prefixes, common metadata keys. |

## Documented surface

- **Endpoint**: `GET /v1/sys/events/subscribe/{eventType}` — WebSocket stream. `{eventType}` is a non-empty string, may contain `*` wildcards (e.g. `kv-v2/data-*`).
- **Formats**: protobuf binary by default; JSON when the `json` query parameter is set to `true`.
- **JSON envelope** (CloudEvents conformant, from the documented example):
  - top level: `id` (unique per notification), `source` (`vault://` + raft node ID or hostname), `specversion` (`1.0`), `type` (currently always `*`), `data` (object), `datacontentype` (`application/cloudevents`), `time` (ISO 8601).
  - `data` contains: `event` (`id` repeat + `metadata` object with string values), `event_type` (the published type), `plugin_info` (`mount_class`, `mount_accessor`, `mount_path`, `plugin`) for plugin-produced events.
  - Documented `metadata` keys: `data_path`, `lease_id`, `modified` (boolean rendered as string), `operation`, `path`, `vault_index` (same format as the `X-Vault-Index` response header).
- **Policy**: `read` capability on `/v1/sys/events/subscribe/{eventType}` (path may contain wildcards). For secrets-related events additionally: `list` + `subscribe` capabilities on the secret path and a `subscribe_event_types` entry in that policy stanza. Policy evaluation for subscriptions is continuous with a short cache — a few minutes of delivery is possible after revocation.
- **Namespaces**: default scope is the requesting namespace only; additional (child) namespace patterns with wildcards may be requested.
- **Multi-node**: only the active node and performance standbys accept subscriptions; other standbys reroute to the active node via `api_addr`. Primary clusters forward events to performance secondaries (cross-cluster wire behavior is out of scope for this project).

## Documented event types (generated automatically by Vault and builtin plugins)

azure: `azure/config-write`, `azure/creds-create`, `azure/creds-create-fail`, `azure/role-create`, `azure/role-update`, `azure/rotate`, `azure/rotate-fail`, `azure/static-role-update`
database: `database/config-delete`, `database/config-write`, `database/creds-create`, `database/reload`, `database/reload-connection`, `database/reload-connection-fail`, `database/reset`, `database/role-create`, `database/role-delete`, `database/role-update`, `database/root-rotate-fail`, `database/root-rotate`, `database/rotate-fail`, `database/rotate`, `database/static-creds-create-fail`, `database/static-creds-create`, `database/static-role-create`, `database/static-role-delete`, `database/static-role-update`
kv: `kv-v1/delete`, `kv-v1/write`, `kv-v2/config-write`, `kv-v2/data-delete`, `kv-v2/data-patch`, `kv-v2/data-write`, `kv-v2/delete`, `kv-v2/destroy`, `kv-v2/metadata-delete`, `kv-v2/metadata-patch`, `kv-v2/metadata-write`, `kv-v2/undelete`
ldap: `ldap/config-delete`, `ldap/config-write`, `ldap/creds-create-fail`, `ldap/creds-create`, `ldap/library-check-in`, `ldap/library-check-out`, `ldap/library-create`, `ldap/library-delete`, `ldap/library-update`, `ldap/role-create`, `ldap/role-delete`, `ldap/role-update`, `ldap/root-rotate-fail`, `ldap/root-rotate`, `ldap/rotate-fail`, `ldap/rotate`, `ldap/static-role-create`, `ldap/static-role-delete`, `ldap/static-role-update`
lease: `lease/expired`, `lease/issued`, `lease/renewed`, `lease/revoked`

(The docs table also lists `lease` metadata fields: `lease_id`, `modified`, `operation`, `path`, and `vault_index` on all but `lease/expired`.)

## Scope decisions (this implementation)

- **In-scope**: the subscription endpoint (WebSocket, JSON + protobuf-binary framing), the event bus in the core, policy enforcement (read on the subscribe path; `list`+`subscribe`+`subscribe_event_types` on secret paths), namespace scoping, filter expressions with the documented selectors, and event emission for the locally-testable producers: KV v1/v2 (12 types), lease events (4 types), LDAP secrets config events, database config/role events, azure config events (all four plugins are in-tree here).
- **Protobuf schema**: the docs reference `EventReceived` in `sdk/logical/event.proto` "in the relevant Vault version" as the wire schema. That file is inside the BSL-licensed Vault tree and is off-limits as implementation input under this project's clean-room rules, so the protobuf message set is defined from the documented JSON field list (EventReceived/Event/PluginInfo equivalents) with field numbers assigned locally. Byte-level protobuf compatibility with Vault Enterprise is therefore NOT claimed; the JSON format (fully documented) is the compat boundary.
- **Backpressure, replay, and reconnection semantics are not documented** in any public page reviewed; none are asserted by these specs.
- **Cross-cluster forwarding** to replication secondaries is out of scope (mission boundary), as is performance-standby rerouting on multi-node clusters.
- **`lease/expired` timing** depends on lease expiry scheduling; the suite only asserts `lease/issued` and `lease/revoked` deterministically (PKI certificate leases) and treats expiry as out of the deterministic window.

## Fixture contract

- Uses the dev server's default `secret/` KV v2 mount for KV events and the in-tree PKI engine for lease events. All written paths use the reserved `compat-evt-` prefix.
- Tokens created for policy cases are cleaned up at suite end (revoke + policy delete; statuses per the generic 200/204/404 convention).
- Do not run concurrent copies of this suite: the case IDs would collide with each other's subscriptions.
