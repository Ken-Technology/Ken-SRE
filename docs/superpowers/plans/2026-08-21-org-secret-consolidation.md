# Organization Secret Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate equivalent secrets into canonical 1Password items, rename their environment-variable contracts across all affected repositories, and open verified PRs without exposing secret values.

**Architecture:** `Ken-SRE` owns a strict, value-free credential registry derived from the 308-row handoff. A local migration tool resolves sources and writes canonical items through stdin, while repository-specific branches consume only canonical `op://` references and names. The migration stays additive until deployment verification.

**Tech Stack:** Python 3.12, Bash, strict YAML, 1Password CLI, Git, Origin CLI, GitHub Actions, repository-native test runners.

---

### Task 1: Lock the registry schema and canonical-name rules

**Files:**
- Create: `infra/github-actions/inventory/canonical-credentials.yaml`
- Create: `infra/github-actions/scripts/lib/canonical_credentials.py`
- Create: `infra/github-actions/tests/test_canonical_credentials.py`
- Modify: `infra/github-actions/tests/test-config.sh`

- [ ] **Step 1: Write failing schema tests**

Require strict YAML with duplicate-key rejection, exact top-level keys, exact scalar types, unique canonical IDs, unique environment-variable aliases, allowed vault names, and explicit dispositions for all 308 handoff rows. Assert that concealed values, digests, prefixes, and value lengths are forbidden registry keys.

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest infra.github-actions.tests.test_canonical_credentials -v
```

Expected: failure because the registry and loader do not exist.

- [ ] **Step 2: Implement the strict loader**

Implement `load_registry(path)`, `validate_registry(document, handoff)`, `canonical_coordinate(row)`, and `validate_complete_coverage(registry, handoff)`. Reject unknown keys recursively and compare the exact set of handoff coordinates.

- [ ] **Step 3: Seed the registry from the reviewed inventory**

Encode every row with one of `canonical-item`, `dedicated-item`, `github-variable`, `github-token`, `oidc`, or `retired`. Record `verification_status`, `source_authority`, `canonical_vault`, `canonical_item`, `canonical_field`, `environment`, and `consumer_repositories` without any value-derived evidence.

- [ ] **Step 4: Run the focused gate**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest infra.github-actions.tests.test_canonical_credentials -v
bash infra/github-actions/tests/test-config.sh inventory
```

Expected: all tests and all inventory assertions pass.

- [ ] **Step 5: Commit**

```bash
git add infra/github-actions/inventory/canonical-credentials.yaml \
  infra/github-actions/scripts/lib/canonical_credentials.py \
  infra/github-actions/tests/test_canonical_credentials.py \
  infra/github-actions/tests/test-config.sh
git commit -m "feat: define canonical credential registry"
```

### Task 2: Add a non-disclosing migration tool

**Files:**
- Create: `infra/github-actions/scripts/consolidate-1password.py`
- Create: `infra/github-actions/tests/test-consolidate-1password.py`
- Modify: `infra/github-actions/inventory/canonical-credentials.yaml`

- [ ] **Step 1: Write failing command-boundary tests**

Use fake `op` and fake SSH executables. Assert that the tool passes values through stdin, never arguments or stdout; rejects symlinks and unsafe temporary paths; clears inherited 1Password tokens before switching accounts; refuses cross-vault writes; reads back item IDs, labels, field types, and concealment; and emits only value-free JSON status.

- [ ] **Step 2: Implement discovery mode**

Add `discover`, `compare`, `populate`, and `verify` subcommands. `discover` reads existing item fields and approved deployed sources. `compare` keeps values in memory and emits only `same-identity`, `different-value`, `different-scope`, or `unresolved`.

- [ ] **Step 3: Implement idempotent item population**

Use `op item get --format=json` for metadata. Pipe JSON templates to `op item create --vault <vault> -` for new items and `op item edit <item-id> --vault <vault>` for exact updates. Never put sensitive assignments in arguments and never use item sharing.

- [ ] **Step 4: Verify without values**

Read every populated item back and assert the expected item ID, vault ID, field label, field type, concealment, and reference path. Record only those structural facts in the registry.

- [ ] **Step 5: Run tests and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest infra.github-actions.tests.test_consolidate_1password -v
git diff --check
git add infra/github-actions/scripts/consolidate-1password.py \
  infra/github-actions/tests/test-consolidate-1password.py \
  infra/github-actions/inventory/canonical-credentials.yaml
git commit -m "feat: add concealed credential migration"
```

### Task 3: Resolve and populate the canonical vault items

**Files:**
- Modify: `infra/github-actions/inventory/canonical-credentials.yaml`
- Create: `infra/github-actions/inventory/credential-migration-ledger.yaml`

- [ ] **Step 1: Validate the three migration identities**

For each temporary service-account token, run `op whoami --format=json` and `op vault list --format=json` in a minimal environment. Require exactly the intended vault and reject unexpected vault visibility.

- [ ] **Step 2: Resolve existing 1Password authorities**

Run discovery against existing readable items. Compare candidate duplicates in memory and require matching environment, provider account, endpoint, and permission scope.

- [ ] **Step 3: Recover missing deployed authorities**

Use the authorized backend root connection to read `/var/www/scraper.api/appsettings.Production.json` into the migration process without printing it. Use scoped QA accounts for other hosts. Do not restart services or change files.

- [ ] **Step 4: Populate canonical items**

Create or update items in `Ken CI Runtime`, `Ken Deploy Nonproduction`, and `Ken Deploy Production`. Keep target-specific SSH identities separate. Mark every written field with its value-free source coordinate and verification status.

- [ ] **Step 5: Re-run verification**

```bash
python3 infra/github-actions/scripts/consolidate-1password.py verify \
  --registry infra/github-actions/inventory/canonical-credentials.yaml \
  --ledger infra/github-actions/inventory/credential-migration-ledger.yaml
```

Expected: every populated field has a structural readback and no output contains a secret value.

- [ ] **Step 6: Commit metadata only**

```bash
git add infra/github-actions/inventory/canonical-credentials.yaml \
  infra/github-actions/inventory/credential-migration-ledger.yaml
git commit -m "feat: record canonical credential authorities"
```

### Task 4: Regenerate the central handoff and broker policy

**Files:**
- Modify: `infra/github-actions/scripts/lib/build_task6_authority_evidence.py`
- Modify: `infra/github-actions/scripts/lib/audit_workflows.py`
- Modify: `infra/github-actions/tests/test_audit_workflows.py`
- Modify: `infra/github-actions/inventory/evidence/task-6-authority-metadata.json`
- Modify: `infra/github-actions/inventory/repositories.yaml`
- Modify: `infra/github-actions/inventory/secrets.yaml`
- Modify: `infra/github-actions/inventory/secret-handoff.yaml`
- Modify: `infra/github-actions/inventory/op-broker-policy.yaml`
- Modify: `infra/github-actions/inventory/broker-runtime.lock.yaml`

- [ ] **Step 1: Write failing canonical-authority tests**

Assert that generated rows point to the canonical item and field, aliases cannot create duplicate items, cross-environment references fail, all 308 coordinates remain covered, and broker actions receive only their exact reviewed fields.

- [ ] **Step 2: Apply canonical mappings in the generator**

Load `canonical-credentials.yaml` as a hashed input. Preserve all observed source coordinates and replace only target authority, disposition, and canonical environment-variable metadata.

- [ ] **Step 3: Regenerate twice**

Run the authority and inventory generators into two clean temporary directories. Require byte-identical output and compare it to the committed artifacts.

- [ ] **Step 4: Run all central gates**

```bash
bash infra/github-actions/tests/test-config.sh all
bash infra/github-actions/tests/test-broker.sh
bash infra/github-actions/tests/test-action-transport.sh
git diff --check
```

Expected: every assertion passes and value scans find no secret material.

- [ ] **Step 5: Commit**

```bash
git add infra/github-actions
git commit -m "feat: bind canonical secret authorities"
```

### Task 5: Prepare isolated repository branches

**Files:**
- No shared implementation files

- [ ] **Step 1: Refresh exact repository heads**

For each inventory repository, fetch `origin`, inspect `origin repo view --json mirrorStatus`, and record the exact default-branch SHA. Do not use a stale local checkout.

- [ ] **Step 2: Create one worktree per affected repository**

Create `feat/canonical-secrets` from the current default branch. Repositories with no required change stay in the ledger with `no-change` evidence and receive no PR.

- [ ] **Step 3: Assign non-overlapping ownership**

Group work by repository. Each worker owns its entire repository branch, including workflow, code, tests, examples, and documentation. No two workers edit the same repository.

### Task 6: Migrate the core application repositories

**Files:**
- `ken-agents`: `.github/workflows/deploy.yml`, `.env.example`, `ken_agents/config.py`, `deploy/docker-compose.platform.yml`, related tests
- `ken-ai-mcp`: `.github/workflows/deploy.yml`, `.env.example`, `src/ken_mcp/config.py`, `src/mongo/config.py`, service file, related tests
- `ken-ai-public-mcp`: deployment workflow and runtime configuration discovered from its refreshed default branch
- `ken-backend`: `.github/workflows/deploy.yml`, `.env.op`, `docs/env-template.txt`, configuration bindings and deploy tests
- `ken-frontend`: `.github/workflows/deploy.yml`, provider/config clients, deployment docs, related tests
- `ken-search`: `.github/workflows/deploy.yml`, production appsettings, infrastructure bindings, configuration tests

- [ ] **Step 1: Add failing old-name and canonical-name tests in each repository**

Tests must prove the canonical name reaches the same configuration binding and that removed spellings no longer appear outside an explicitly documented compatibility adapter.

- [ ] **Step 2: Rename workflow, runtime, template, and documentation contracts together**

Apply the approved mappings. Preserve framework section names when required, including the DeepSeek credential consumed through an OpenAI-compatible client in `ken-search`.

- [ ] **Step 3: Run repository gates**

```bash
# ken-agents
uv run pytest tests/ -q
# ken-ai-mcp
./scripts/test.sh
# ken-backend
./scripts/test.sh full
dotnet build "Ken.Scraper/Ken.Scraper.sln" --verbosity quiet
# ken-frontend
pnpm lint && pnpm test:unit && pnpm build
# ken-search
dotnet test Ken.Search.sln --no-restore
```

- [ ] **Step 4: Commit each repository separately**

Use `feat: consolidate environment secrets` on each feature branch.

### Task 7: Migrate the remaining private repositories

**Files:**
- `dev-workstation`, `ken-scraping`, `ken-brain`, `ken-website`, `client-system`, `ken-hermes-clickup`, `ken-help`, `ken-daily`, `ken-automations`, `ken-analytics`, `gtm`, `ken-email-deliverability-dashboard`, `ken-vexa-mcp-auth`, `ken-cms`, `ken-ai-optimizer`

- [ ] **Step 1: Update every direct environment read and workflow reference**

Use the central registry. Keep runtime PATs separate from built-in `GITHUB_TOKEN`, retain target-specific SSH items, move the embedded website `INDEXNOW_KEY` into 1Password, and keep PostHog key types separate.

- [ ] **Step 2: Update examples, compose files, validators, and tests**

Reject old spellings unless a time-bounded compatibility adapter is required for rolling deployment. Compatibility adapters must prefer the canonical name and have a removal note in the PR documentation.

- [ ] **Step 3: Run each repository's documented focused tests**

Read `AGENTS.md`, `CLAUDE.md`, CI workflows, and existing deployment tests in that repository. Record the exact commands and results in the PR body.

- [ ] **Step 4: Commit each repository separately**

Use `feat: consolidate environment secrets` on each feature branch.

### Task 8: Remove static publisher secrets where supported

**Files:**
- `Ken-SRE/.github/workflows/*publish*`
- `ken-scraping/.github/workflows/*publish*`
- Registry publishing configuration and tests in those repositories

- [ ] **Step 1: Add failing permission and publisher tests**

Require `id-token: write` only on the exact publishing job and reject static registry-token references when trusted publishing is supported.

- [ ] **Step 2: Convert supported publishers to OIDC**

Use PyPI Trusted Publishing for `derisk-mono` in environment `pypi`. Convert other registries only when their current official flow supports repository-bound trusted publishing.

- [ ] **Step 3: Run package build and metadata checks**

```bash
python -m build --sdist --wheel .
python -m twine check dist/*
```

- [ ] **Step 4: Commit**

Use `feat: use trusted package publishing` in each affected repository.

### Task 9: Open and drive the PR fleet

**Files:**
- Create or modify each repository's `docs/changes/2026-08-21-secret-consolidation.md` where required by its instructions

- [ ] **Step 1: Run local review**

Use the medium review panel for each branch. Apply valid findings, rerun focused tests, and record rejected findings with evidence.

- [ ] **Step 2: Push through Origin and open normal PRs**

Run `origin repo view --json mirrorStatus` first. Use `origin pr create --status open` for native repositories and `gh pr create` only for inbound repositories whose PR objects remain on GitHub.

- [ ] **Step 3: Drive Grok CI and repository CI green**

Wait for Grok CI on each latest SHA, apply valid findings, and inspect failed Actions logs before changing code. Cap review rounds at three under medium review.

- [ ] **Step 4: Record dependency order**

Central authority PR first, then repository PRs. Do not merge or deploy in `finish=pr` mode.

### Task 10: Produce the cutover and retirement handoff

**Files:**
- Create: `infra/github-actions/inventory/credential-retirement-ledger.yaml`
- Modify: `infra/github-actions/runbooks/cutover.md`

- [ ] **Step 1: Record old authorities without deleting them**

For every migrated reference, record the old GitHub secret or 1Password coordinate, replacement coordinate, PR, deployment status, live verification status, and retirement eligibility.

- [ ] **Step 2: Add the read-only service-account gate**

Require three replacement service-account identities with read-only access to exactly one vault each. Reject write, share, or cross-vault access before credential installation.

- [ ] **Step 3: Verify final offline state**

```bash
bash infra/github-actions/tests/test-config.sh all
git diff --check
git status --short
```

Expected: all offline checks pass, PRs are green, old authorities remain intact, and live cutover is blocked only on the documented read-only service accounts and deployment approval.
