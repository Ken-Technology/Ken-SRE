# Organization secret consolidation specification

Status: approved by Cristian on 2026-08-21.

## Goal

Replace repository-specific copies and inconsistent environment-variable names with one canonical 1Password authority for each real credential identity, then update every affected repository in one coordinated PR pass.

## Scope

The migration covers the 25 repositories and 308 secret references recorded in `infra/github-actions/inventory/secret-handoff.yaml`. It includes GitHub Actions workflows, application configuration, deployment templates, tests, examples, and operational documentation.

The migration does not merge credentials merely because their labels look alike. Two references share an item only when the value, provider account, permission scope, endpoint, trust environment, and deployment target match.

## Trust boundaries

The three vaults are separate authorities:

- `Ken CI Runtime` holds credentials used by isolated CI jobs for builds, tests, validation, publishing, and approved automation. It excludes deployment-target access.
- `Ken Deploy Nonproduction` holds credentials used only for development, staging, and other nonproduction deployments and verification.
- `Ken Deploy Production` holds credentials used only for restricted production deployment and verification.

Production, nonproduction, and CI credentials never share an item, even when their field names match.

## Canonical item model

Use one 1Password item per provider account or deployment identity in each vault. Repositories consume fields from that shared item.

Examples:

- `openai-production` with `OPENAI_API_KEY`
- `openrouter-production` with `OPENROUTER_API_KEY`
- `langfuse-production` with `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, and `LANGFUSE_BASE_URL`
- `aws-production` with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, only when the IAM identity and permissions match
- a target-specific deployment item with service-prefixed host, user, key, port, and known-host fields

Do not create one enormous vault item. It would give unrelated jobs access to unrelated credentials and make rotation risky.

## Canonical names

Environment-variable names use uppercase snake case and describe the credential rather than the repository that first owned it. The first proven normalizations are:

| Previous names | Canonical name |
|---|---|
| `OPEN_AI_API_KEY` | `OPENAI_API_KEY` |
| `OPEN_ROUTER_API_KEY` | `OPENROUTER_API_KEY` |
| `xAI_API_KEY` | `XAI_API_KEY` |
| `FIREWORKS_AI_API_KEY` | `FIREWORKS_API_KEY` |
| `TOGETHER_AI_API_KEY` | `TOGETHER_API_KEY` |
| `AWS_ACCESS_KEY` | `AWS_ACCESS_KEY_ID` |
| `FIND_MAIL_API_KEY` | `FINDYMAIL_API_KEY` |
| `DB_CONNECTION_STRING2` | `KEN_DB_CONNECTION_STRING` |
| `MONGO_CONNECTION_STRING2` | `KEN_MONGO_CONNECTION_STRING` |
| `LANGFUSE_HOST` and `LANGFUSE_BASEURL` | `LANGFUSE_BASE_URL` |

Application configuration sections may retain framework-required names. A workflow alias is not considered migrated until the application binding, tests, examples, and documentation use the canonical contract or an explicitly tested compatibility adapter.

## Required separations

The migration keeps these identities separate:

- browser-visible `NEXT_PUBLIC_*` values and server-side secrets
- GitHub's ephemeral `GITHUB_TOKEN` and runtime personal access tokens
- OpenAI and OpenRouter
- direct DeepSeek and Doubleword credentials
- Langfuse public and secret keys
- PostHog project tokens, personal API keys, and server API keys
- Stripe API keys and webhook signing secrets
- Clerk application secrets and OAuth client credentials
- MySQL and MongoDB credentials
- deployment SSH identities for different hosts or users
- Cloudflare credentials with different zones, resources, or permissions
- credentials from different environments

## Secure value handling

Secret values may flow only through process memory, protected file descriptors, mode-0600 temporary files, 1Password CLI stdin, or GitHub secret stdin. Commands must not print values. Reports store labels, item IDs, field types, scopes, and status only. They do not store secret values, reversible hashes, prefixes, or lengths that expose sensitive structure.

Candidate duplicates are compared in memory. A match also requires the same provider account, scope, endpoint, and environment. The migration creates the canonical item first and leaves the old source intact until the consuming PR is deployed and verified.

## Source priority

Resolve each authority in this order:

1. Existing readable 1Password items.
2. Existing deployed configuration, read without restarting or modifying services.
3. Existing GitHub secret metadata and repository configuration.
4. A documented independent authority creation or retirement decision.

The backend production source is `/var/www/scraper.api/appsettings.Production.json` on `185.183.35.189`. Read it only through the explicitly authorized root connection and never print its secret-bearing contents.

## Service accounts

The three current service accounts have read, write, and share permissions. Use them only as temporary migration writers. Never install their tokens on `devws`, a runner, or a deployment guest.

Before live runner cutover, Cristian must replace them with read-only service accounts scoped to their single vault. The final runtime token installation remains blocked until those replacement accounts exist and pass identity and vault-scope readback.

## Repository migration

Each affected repository gets an isolated branch and a normal PR. A repository change is atomic:

- workflow references use the canonical 1Password item and field
- transient shell names use the canonical environment variable
- application bindings and direct environment reads use the canonical name
- examples and documentation use the canonical name
- focused tests prove the old spelling is absent or handled only by an intentional compatibility adapter

Public repositories remain secretless where registry-native OIDC or trusted publishing can replace static tokens.

The central inventory and broker authority change before dependent repository PRs. Repository PRs may be opened in parallel after that dependency is published.

## Rollback and retirement

The migration is additive until live verification. It does not delete old 1Password items or GitHub secrets during the PR pass. A rollback points a workflow back to the prior authority while the old value still exists.

After deployment verification, a separate retirement ledger authorizes deletion of obsolete GitHub secrets, old 1Password fields, and temporary migration service-account tokens.

## Success criteria

- All 308 references have a canonical disposition: shared item, dedicated item, GitHub variable, OIDC, built-in token, or retired.
- No unresolved reference is silently replaced with an invented value.
- Proven shared credentials have one canonical item per environment and scope.
- Every affected codebase uses the canonical environment-variable name.
- Every changed repository has a PR with its focused verification and green CI.
- No secret value appears in Git, PR text, logs, or reports.
- Old authorities remain available until live deployment verification.
- Runtime service accounts are read-only before any runner or deployment host receives them.
