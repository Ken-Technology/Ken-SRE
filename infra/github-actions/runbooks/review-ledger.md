# CI cutover plan review ledger

Source: `/private/tmp/grok-ci-plan-review-2.md`

Reviewer: Grok 4.6 high

Status: 11 findings accepted, 0 rejected.

This ledger records accepted corrections only. It contains no secret values.

### Finding 1 — Combined build-and-deploy jobs

Severity: Critical
Accepted. Combined jobs such as `ken-backend` `deploy.yml` must be split later into `ken-ci` `heavy` artifact production and `ken-deploy` download-only consumption. Inventory flags every such job `COMBINED_BUILD_AND_DEPLOY`. Deployment runners must not compile or test source.

### Finding 2 — Ten CI runners, not twelve registered

Severity: Critical
Accepted. Target capacity is ten CI runners plus two deploy runners. `ken-ci-standard-09` and `ken-ci-standard-10` may be defined as reserved/disabled only. They are not registered.

### Finding 3 — 1Password token injection

Severity: Critical
Accepted. Service-account tokens are unit-scoped systemd credentials wrapped by `op run`. Ban `1password/load-secrets-action` and any GitHub secret named `OP_SERVICE_ACCOUNT_TOKEN`. Production identity exists only on `ken-deploy-production-01`.

### Finding 4 — Classify by target, not environment name

Severity: Important
Accepted. Production impact is determined by target host and side effect. `ken-backend` environment `Preprod` is production and maps to `ken-deploy-production`. Other mismatched display names are inventoried the same way.

### Finding 5 — Record environment protection rules

Severity: Important
Accepted. Task 2 records required reviewers, prevent-self-review, wait timer, and deployment-branch rules. A required reviewer outside the cutover operator is an external hard stop. Protection is not weakened.

### Finding 6 — Isolate CI and deploy networks

Severity: Important
Accepted. Later provisioning puts guests on separate networks. `ken-ci` default-denies the host, `ken-deploy`, and production ports. This inventory does not change hosts.

### Finding 7 — GitHub secret values are unrecoverable

Severity: Important
Accepted. Every referenced name records a source authority. If the value is not readable without fetching a secret, `rotation_required` is true. Values are never read or logged.

### Finding 8 — Preserve existing Grok review

Severity: Important
Accepted. Jobs using `[self-hosted, grok-review]` stay on the six `hetzner-grok-review-*` runners. A Grok workflow `gate` companion currently on `[self-hosted, ken-ci]` is classified with the existing Grok review class, not the new general CI pool.

### Finding 9 — Re-measure host disk and memory

Severity: Important
Accepted. Task 3 re-measures `df -h /` and `MemAvailable` before packages or guests. The host snapshot in this inventory is dated evidence, not a start authorization.

### Finding 10 — Single planned human stop

Severity: Important
Accepted. Spec §11 is the single Task 6 phrase `1Password ready`. GitHub/Origin remain preflights. Freeze notice and teardown stay evidence-gated.

### Finding 11 — Hosted fallback is last resort

Severity: Important
Accepted. Organization plan is Free with 2,000 private hosted minutes. Keep the existing `$0` Actions overage guard. Do not fail over every private repository to `ubuntu-latest`, and do not hard-code a 3,000-minute Team assumption.
