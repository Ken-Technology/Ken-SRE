# FEATURE: Organization CI and credential consolidation

Date: 2026-08-21  
Repo: Ken-SRE  
Branch: `fix/task6-split-canonical-items`  
Type: feature

## How this helps

Ken repositories now share one reviewed credential registry and a fail-closed self-hosted Actions design. Duplicate credentials move into canonical 1Password items while environment-specific values remain separate.

## ClickUp message

```
FEATURE: Organization CI and credential consolidation

Ken repositories now share one reviewed credential registry and a fail-closed self-hosted Actions design. Duplicate credentials move into canonical 1Password items while environment-specific values remain separate.

Developer-speak:
Ken-SRE now records the 25-repository credential inventory, canonical 1Password handoff, three service-account boundaries, isolated runner and deployment transport contracts, offline VM build inputs, and strict broker policy. The implementation remains disabled for live execution until the external endpoint, 1Password Linux canary, image, and approval receipts exist.
```

## Summary

This change consolidates repository credential names and 1Password item ownership across the Ken organization. It also defines the isolated CI runners, deployment broker, offline VM images, firewall policy, and transaction receipts required to replace the previous runner and secret layout.

The repository does not authorize a live cutover. `live_apply_allowed`, installation authorization, transport enablement, and action enablement remain false until the committed external blockers have verified receipts.

## What changed

- Added the canonical credential registry, source evidence, migration ledgers, and value-free handoff inventory.
- Added resumable 1Password population tools with strict readback, duplicate-key rejection, rate-limit handling, and value-free receipts.
- Split production broker actions across the canonical Vexa, website deploy, Beehiiv, and blog-sync items.
- Added isolated runner, broker, transaction, VM image, firewall, proxy, and systemd contracts with fail-closed tests.
- Bound Task 4, Task 6, and Task 7 artifacts through exact commit, tree, blob, and SHA-256 identities without recursive hashes.

## Design decisions

- Shared credentials use one canonical item per environment. Repositories reference the shared item instead of keeping renamed copies.
- CI, nonproduction deployment, and production deployment use three separate 1Password service accounts and vaults.
- GitHub stores only the temporary bootstrap token during migration. Runtime credentials stay in 1Password and enter a job through fixed broker fields.
- Production actions stay disabled until the operator supplies the reviewed external receipts and performs the single approved cutover.

## Testing

Fresh offline verification on the final branch passed:

- `bash infra/github-actions/tests/test-config.sh inventory`: 16 assertions
- `bash infra/github-actions/tests/test-broker.sh`: 14 assertions and 53 Python tests, with 2 Linux-only skips on macOS
- `bash infra/github-actions/tests/test-action-transport.sh`: 6 assertions and 29 Python tests
- `bash infra/github-actions/tests/test-config.sh vm-static`: 169 assertions
- `bash infra/github-actions/tests/test-config.sh runners`: all contract, behavior, and test markers
- `bash infra/github-actions/tests/test-config.sh host`: 45 assertions

No SQL migration is required. No runner, VM, systemd unit, broker, firewall, repository deployment, or live cutover changed during this work.
