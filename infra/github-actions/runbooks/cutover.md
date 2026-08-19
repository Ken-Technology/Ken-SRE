# Organization Actions cutover runbook

This runbook is the sanitized evidence log for the self-hosted Actions cutover. Later tasks append commands and readbacks. No secret values are recorded here.

## Task 1 — Administrative access

Captured 2026-08-19. No repository, runner, environment, secret, billing, or host state was changed.

| Check | Result |
|---|---|
| GitHub identity | `cristian-frunze`; `admin:org`, `repo`, `workflow` scopes |
| Organization | `Ken-Technology`; plan `free`; 5 seats filled |
| Origin | Authenticated for `ken-so` namespace |
| 1Password | Service account can list vault names only: `All Resources`, `Development`, `Email`, `ken-website`, `Marketing` |
| devws SSH | `root@167.235.8.250` read-only; KVM present; libvirt absent |
| Worldstream SSH | `root@185.183.35.189` read-only; ten `ws-ken-ci-*` units active |

Task 1 produced no Ken-SRE commit. Access is sufficient for read-only inventory.

## Task 2 — Organization baseline

Authoritative files:

- `infra/github-actions/inventory/repositories.yaml`
- `infra/github-actions/inventory/runners.yaml`
- `infra/github-actions/inventory/secrets.yaml`

Regenerate with:

```bash
bash infra/github-actions/scripts/audit-workflows.sh --org Ken-Technology --output-dir infra/github-actions/inventory
```

The collector queries names and metadata only. Secret-value endpoints are denylisted.

### Binding decisions applied

- 25 active repositories: 22 private, 3 public. Live GitHub default-branch state is authority.
- Organization plan is Free. Official private hosted allowance is 2,000 minutes. Existing `$0` Actions overage guard is retained.
- Organization runner snapshot is recorded with timestamp. Generation stays deterministic if the Blacksmith count changes later.
- Six `[self-hosted, grok-review]` repository runners remain an unchanged class. Grok `gate` companions stay in that class.
- Production impact uses target and side effect. `ken-backend` environment `Preprod` is production.
- Combined build-and-deploy jobs are flagged for later split.
- Target runner capacity is ten CI plus two deploy. Runners `09`/`10` are reserved/disabled only.

### Evidence still unavailable without a value-safe source

- Long-lived GitHub secret values (unrecoverable; `rotation_required: true`)
- Blacksmith previous-month invoice and current unbilled usage (planning baseline `$130` remains unverified)
- GitHub organization hooks (`admin:org_hook` missing; 404)

Validate:

```bash
bash infra/github-actions/tests/test-config.sh inventory
```
