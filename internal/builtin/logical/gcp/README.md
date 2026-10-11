<!-- SPDX-License-Identifier: MPL-2.0 -->
# Configuration-only cloud backend

Clean-room implementation from the public Vault v2.x API documentation and
`compat/specs/plugin-rotation-seal/{00-plugin-identity,10-provider-rotation}.yaml`.
No Vault implementation source was consulted.

Configuration/role writes and deletes affect local OpenBao storage only and
return a warning. No ambient credentials are loaded. There is no network client,
login endpoint, scheduler, remote validation, token issuance or provisioning.
`verify_connection=true`, credential issuance and explicit rotation return errors.
Scheduling and workload identity fields are stored and validated, not executed.
Secrets and the requested subscription/resource-group identifiers are omitted
from configuration reads. These omissions intentionally prioritize the task's
redaction contract over public API examples that expose some identifiers.

Shared implementation is in `credential/aws/configonly`, kept inside the assigned
cloud package lane. GCP bindings are syntax-validated and returned as configured;
no generated service-account identity or cloud-derived metadata is fabricated.
Cloud resource existence and permissions cannot be validated. AWS principal ID
resolution requires cloud access and is rejected; use
`resolve_aws_unique_ids=false` for local ARN constraint storage.
