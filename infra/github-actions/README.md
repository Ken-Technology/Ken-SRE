# GitHub Actions infrastructure

This directory holds the inventory, host setup, runner configuration, and cutover records for Ken's self-hosted GitHub Actions platform.

## Live host gate

The fresh root-filesystem readback found about 165 GiB free after the Grok process owner cleaned its transient worktrees. Treat that number as dated evidence. Always run the live preflight immediately before apply. `provision-host.sh` requires at least 25 GiB free on `/` before it opens the SSH apply phase, so a later drop in free space stops the run before `apt-get update` or package installation.

The script reports root consumers and an `apt-get -s autoremove` simulation during preflight. It does not delete logs, caches, containers, volumes, application data, runner data, or user files. If the live gate fails again, root-disk remediation needs a separate readback and approval.

## Host provisioning

The only accepted target is `root@167.235.8.250`.

Run the focused tests first:

```bash
bash infra/github-actions/tests/test-config.sh host
```

Run the read-only preflight and print the approved change set:

```bash
bash infra/github-actions/scripts/provision-host.sh --dry-run root@167.235.8.250
```

Apply after every gate passes:

```bash
bash infra/github-actions/scripts/provision-host.sh root@167.235.8.250
```

The apply step installs these packages idempotently:

```text
qemu-kvm
libvirt-daemon-system
libvirt-clients
virtinst
cloud-image-utils
jq
nftables
dnsmasq-base
libguestfs-tools
```

`dnsmasq-base` is a Recommends of `libvirt-daemon-system` on Ubuntu 24.04, so `--no-install-recommends` does not install it. That package provides `/usr/sbin/dnsmasq`, which libvirt needs to start the NAT networks. The script requires that binary before `virsh net-start` and does not install the service-owning `dnsmasq` package.

`libguestfs-tools` provides `virt-customize`. Task 4 uses it to seed guest packages into a checksum-verified, derived qcow2 image before either VM starts, so the deployment guest never needs temporary access to Ubuntu package mirrors.

It enables `libvirtd`, creates the `ken-actions` directory pool, and creates two NAT networks:

| Resource | Value |
| --- | --- |
| Image storage | `/mnt/data/libvirt/images` |
| Cloud-init and network definitions | `/mnt/data/libvirt/seed` |
| Libvirt pool | `ken-actions` |
| CI network | `ken-ci-net`, bridge `virbr-ci`, `192.168.210.0/24` |
| Deploy network | `ken-deploy-net`, bridge `virbr-deploy`, `192.168.211.0/24` |

Task 4 must attach CI guests only to `ken-ci-net` and deploy guests only to `ken-deploy-net`. Do not attach either guest to libvirt's `default` network. The host script reads `default` during verification but does not modify it.

Before changing libvirt resources, the script writes their existence, persistence, active state, autostart state, XML, and pool target to a root-only directory such as `/var/tmp/ken-actions-host.ABC123`. A successful run prints that exact rollback directory and a `RESOURCE_CHANGE` line for the pool and each network. Keep the directory until Task 4 is verified.

## Safety gates

Provisioning stops unless all of these conditions hold:

- `/` has at least 25 GiB free before package installation and 20 GiB after it.
- `/` has at least 100,000 free inodes.
- `/mnt/data` is its own read-write mount with at least 850 GiB and 100,000 inodes free.
- `/mnt/data/libvirt`, `images`, and `seed` contain no symlink or canonical-path escape, and every created directory remains on the same read-write filesystem as `/mnt/data`.
- `MemAvailable` is at least 128 GiB before VM creation.
- `/dev/kvm` is a readable and writable character device.
- All six named `hetzner-grok-review-*` runner services exist and are active.
- `jq` is already available for read-only, field-filtered Docker inspection before any package mutation.
- The two approved `/24` networks do not overlap any host route, existing bridge, Docker network, or other libvirt network. An existing target network must match the full NAT, bridge, address, netmask, and DHCP contract before any package or network mutation.

The apply step requires complete identities for the six exact Grok runner units and exactly one `Runner.Listener` under each expected runner path before package installation, then repeats those checks at final readback. Unit identity includes loaded/active/running state and a nonzero `MainPID`, so a missing, stopped, or restarted runner generation fails verification. Failed or incomplete `systemctl show` and `pgrep` probes fail closed. Per-job `Runner.Worker` processes are intentionally excluded: they normally start and exit as jobs move through the queue and are not service-health identities. The same snapshot protects Elasticsearch, Docker, running containers, and listening ports. Listening sockets are compared by normalized protocol, state, local endpoint, and peer endpoint; volatile process PID/FD annotations and whitespace are excluded. Docker JSON is filtered to container ID, name, image, status, start time, restart count, and health only; container environment values and other inspect data are never written to the snapshot or command output. A container without a healthcheck records `none`. Container identity includes start time, restart count, and health, so a restarted container cannot pass merely because it returned to `running`. New libvirt processes and ports are allowed; missing or changed protected logical listeners and restarted protected services are not. The 128 GiB `MemAvailable` floor is checked again after pool and network convergence.

Task 4 has a separate post-start limit. Both guests must leave at least 32 GiB host `MemAvailable` while Elasticsearch and all six Grok runners stay healthy.

## Readback

After a successful apply, run this read-only host check and save its output with the cutover evidence:

```bash
ssh root@167.235.8.250 '
  df -h / /mnt/data
  df -i / /mnt/data
  free -h
  swapon --show
  systemctl is-active libvirtd elasticsearch docker
  virsh nodeinfo
  virsh pool-info ken-actions
  virsh net-info default
  virsh net-info ken-ci-net
  virsh net-info ken-deploy-net
  findmnt /mnt/data
'
```

Check the protected runners separately so a missing unit is obvious:

```bash
ssh root@167.235.8.250 '
  for unit in \
    actions.runner.Ken-Technology-ken-agents.hetzner-grok-review-ken-agents.service \
    actions.runner.Ken-Technology-ken-ai-mcp.hetzner-grok-review-ken-ai-mcp.service \
    actions.runner.Ken-Technology-ken-backend.hetzner-grok-review-ken-backend.service \
    actions.runner.Ken-Technology-ken-frontend.hetzner-grok-review-ken-frontend.service \
    actions.runner.Ken-Technology-ken-scraping.hetzner-grok-review-ken-scraping.service \
    actions.runner.Ken-Technology-ken-search.hetzner-grok-review-ken-search.service
  do
    printf "%s " "$unit"
    systemctl is-active "$unit"
  done
'
```

Any failed readback blocks VM creation.

## Rollback

If apply fails after resource-state capture, the script automatically restores the pool and networks in reverse order. Resources created by the failed run are destroyed and undefined; preexisting resources are returned to their recorded active and autostart states. The rollback directory is retained for inspection, and the failure output must include `AUTO_ROLLBACK_STATUS=ok`. A failed automatic rollback blocks all later tasks.

After a successful apply, use the exact `Rollback state:` path printed by that run if Task 4 has not created guests and rollback is required:

```bash
bash infra/github-actions/scripts/provision-host.sh \
  --rollback /var/tmp/ken-actions-host.ABC123 \
  root@167.235.8.250
```

The rollback command accepts only a real, non-symlinked state directory beneath `/var/tmp/ken-actions-host.*`, requires all three state manifests, and restores the captured active and autostart values. It does not delete `/mnt/data/libvirt`, package files, guest disks, seed data, or forensic evidence. Do not roll back a pool or network after a guest uses it; stop and inspect dependencies first. Package removal is never automatic. Review `/var/log/apt/history.log` and the live dependency graph before considering it.

Rollback is complete only after the readback above shows the original pool/network state, original protected-service state, and all six Grok runners active.

## Task 4 VM definitions and approval boundary

Task 4 defines `ken-ci` (32 vCPU, 112 GiB RAM, 750 GiB disk) and `ken-deploy` (4 vCPU, 12 GiB RAM, 80 GiB disk), their cloud-init contracts, and a host firewall renderer. Disk capacity and the offline-customization requirement are recorded in machine-readable XML metadata. The definitions contain no credentials. The CI guest uses only `ken-ci-net`; the deployment guest uses only `ken-deploy-net`. Deployment HTTPS is limited to the inventory-reviewed GitHub and 1Password endpoints in `scripts/lib/vm-firewall.sh`, and deployment SSH is limited to `185.183.35.189`.

Cloudflare remains blocked. The current inventory has no normalized, machine-readable Cloudflare deployment target, so `api.cloudflare.com` is not hardcoded into the allowlist. A later task must first add and audit that target record.

The guest image must be built from a checksum-verified Ubuntu 24.04 qcow2 using `virt-customize --no-network` and a reviewed local package cache; the host prerequisite for that operation is committed separately. The builder must write `/etc/ken-actions-image-manifest.sha256` as root. It may not be group- or world-writable. Its ordered entries must exactly match the reviewed file list embedded in the guest bootstrap script, use lowercase SHA-256 values and root-relative paths, and contain no comments, blank lines, duplicates, extra paths, symlinks, or paths that resolve outside the image root.

Cloud-init performs no package installation or update. It invokes one `set -euo pipefail` bootstrap script per guest. That script verifies the complete package list, manifest structure, ownership, permissions, approved file topology, checksums, and the deployment guest's `op` binary before it runs `loginctl` or any service command. Any verification error stops the complete first-boot chain. Neither guest may receive temporary access to Ubuntu package mirrors.

The dedicated host policy drops all CI IPv6 and the complete configured non-global/reserved IPv4 set before permitting IPv4 web traffic. That set includes the dev host public address `167.235.8.250`, the Worldstream production address, bridge/private ranges, loopback, link-local, Tailscale CGNAT, documentation, benchmark, multicast, and reserved ranges. Forwarded NEW or invalid traffic into either guest bridge is dropped; only established/related return traffic is accepted. The host input path similarly accepts established/related replies from each bridge before allowing DHCP/DNS and dropping every other guest-originated host connection. This preserves host-initiated admin SSH without exposing host services to the guests.

Live VM creation is intentionally fail-closed pending one consolidated approval for these exact persistent host units:

1. `ken-actions-vm-firewall.service` resolves the inventory-approved endpoint list, atomically replaces only the dedicated `inet ken_actions_vms` table, verifies its generation, and proves all non-Ken nftables state is unchanged. It must never write a global `/etc/nftables.conf` or run `flush ruleset`.
2. `ken-actions-vm-firewall.timer` refreshes endpoint DNS every 15 minutes. Resolver failure retains the last verified generation and fails closed; a changed answer is applied atomically and read back before success.
3. `ken-actions-vms.service` requires and starts after `libvirtd` and the firewall service. It rechecks `/mnt/data`, the full VM CPU/memory/disk/network contract, firewall generation, Docker, Elasticsearch, and all protected Grok runner services before starting either guest.

These units are required for reboot persistence and for proving isolation is loaded before a guest can start. They are not included or installed without that approval. Until then, non-dry-run provisioning refuses locally before invoking SSH:

```bash
bash infra/github-actions/scripts/provision-vms.sh root@167.235.8.250
```

Use the static suite for the completed definitions and refusal boundary:

```bash
bash infra/github-actions/tests/test-config.sh vm-static
```

The full acceptance target stays intentionally red and is labeled `PENDING APPROVAL` until the three units exist and the fake-host apply test proves firewall-before-VM ordering, restart-safe convergence, disk/network contracts, and guest-agent readiness:

```bash
bash infra/github-actions/tests/test-config.sh vm-definitions
```

## Task 5 offline runner platform

`inventory/runner-platform.yaml` is the reviewed desired state for the new runner pools. It reserves 14 identities and enables 12: eight standard CI slots, two heavy CI slots, and one nonproduction plus one production deployment slot. `ken-ci-standard-09` and `ken-ci-standard-10` remain disabled capacity reservations and must not create accounts, units, or GitHub registrations. The Task 2 `inventory/runners.yaml` file remains observed evidence and is not an operational input.

Every identity has a fixed user, UID/GID, non-overlapping 65,536-entry subordinate-ID range, runner/work path, Docker path, and parent slice. Standard slices are capped at `200%` CPU and 8 GiB; heavy slices at `400%` and 16 GiB; deployment slices at `200%` and 5 GiB. All have swap disabled. The listener and that identity's separate rootless Docker daemon share the same slice. Deployment Docker stays disabled until a reviewed workflow proves it is required.

The runner release is pinned to Actions runner `2.336.0`, asset `483731096`, with SHA-256 `04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d`. Provenance is the official GitHub release API record `356901421`, read on 2026-08-19. Live installation must re-download the exact archive, verify that digest before extraction, keep the binaries root-owned and read-only, and configure `--disableupdate`.

The `Ken Private CI` and `Ken Private Deploy` desired groups both use selected-repository visibility, reject public repositories, and pin the reviewed IDs of the 15 private repositories in the inventory contract. Before any group mutation, a live implementation must resolve those names again through the GitHub API and fail if an ID, visibility, archival state, or inventory generation differs. It must not change Default, Blacksmith, Grok, or Worldstream groups.

Runner listeners load no credentials. Every Task 5 record remains:

```yaml
credential_profile: none
credential_delivery: broker-only-pending-task-6
```

The listener units do not expose a 1Password token, systemd credential directory, `ken-op-exec`, the rootful Docker socket, sudo, or Docker-group membership. Task 6 alone owns the broker and credential delivery.

`ken-runner-cleanup` is the root-owned listener admission and `ExecStopPost` boundary. Before each listener start, it recovers the prior workspace, proves a root-owned clean marker, and replaces that marker with persistent dirty evidence for the admitted job. A failed post-job cleanup or dirty boot therefore cannot reach `run.sh`; `Restart=always` retries only the cleanup gate. Only a fully successful cleanup restores the clean marker.

The helper validates the exact runner name, numeric service UID, canonical base/child paths, ownership, filesystem device, and non-symlink state before deleting only that runner's work directory. For CI identities it contacts only that runner's rootless Docker socket. It explicitly preserves Docker's built-in `bridge`, `host`, and `none` networks and removes only custom networks from that per-runner daemon. Container, custom-network, or volume failures are accumulated so the bounded workspace cleanup still runs, but the helper returns failure and leaves the runner dirty. It never invokes a global prune or a rootful socket. The other identities' caches, sockets, processes, and workspaces are out of scope.

Each rendered CI listener `Requires`, starts `After`, and `BindsTo` its exact `ken-runner-docker@<name>.service`. The rootless daemon must reach systemd readiness and its runner-owned socket must pass the pre-start cleanup check before the listener can accept a job. Deployment listeners have no Docker dependency or `DOCKER_HOST`. Registration and read-only verification reject any GitHub record, local record, account/subordinate-ID state, unit, directory, ready marker, dirty/clean marker, runtime directory, or socket for disabled reservations 09 and 10.

### Offline checks and live boundary

Run the complete Task 5 offline suite with:

```bash
bash infra/github-actions/tests/test-config.sh runners
```

The suite exercises schema and unit security, fake selected-repository resolution, missing/unhealthy Task 4 evidence, low-memory gates, archive checksum failure, exact/idempotent registration, local/GitHub drift, rollback, disabled-state mutations, read-only verification, built-in-network handling, persistent dirty/clean admission, daemon readiness, cleanup failure, and adversarial two-runner isolation.

The only supported controller preview is read-only:

```bash
bash infra/github-actions/scripts/register-runners.sh \
  --org Ken-Technology \
  --all \
  --dry-run

bash infra/github-actions/scripts/verify-platform.sh runners --dry-run
```

Task 5 deliberately contains no SSH or GitHub mutation transport. Any non-test registration or verification call fails locally until Task 4 is reviewed, its three persistent-unit approval is granted, the VMs are provisioned, and fresh evidence proves the exact host, at least 32 GiB host memory headroom, both VM memory contracts and health, firewall generation, and guest isolation. The fake transport exists only for hermetic tests; it does not install accounts, start services, create GitHub groups, or register runners.
