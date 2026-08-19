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

The apply step snapshots the Grok runner units, Elasticsearch, Docker, matching processes, running containers, and listening ports before package installation. Docker JSON is filtered to container ID, name, image, status, start time, restart count, and health only; container environment values and other inspect data are never written to the snapshot or command output. A container without a healthcheck records `none`. Container identity includes start time, restart count, and health, so a restarted container cannot pass merely because it returned to `running`. New libvirt processes and ports are allowed; missing or restarted protected processes are not. The 128 GiB `MemAvailable` floor is checked again after pool and network convergence.

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

Task 4 defines `ken-ci` (32 vCPU, 112 GiB RAM, 750 GiB disk) and `ken-deploy` (4 vCPU, 12 GiB RAM, 80 GiB disk), their cloud-init contracts, and a host firewall renderer. The definitions contain no credentials. The CI guest uses only `ken-ci-net`; the deployment guest uses only `ken-deploy-net`. Deployment HTTPS is limited to the inventory-reviewed GitHub and 1Password endpoints in `scripts/lib/vm-firewall.sh`, and deployment SSH is limited to `185.183.35.189`.

Cloudflare remains blocked. The current inventory has no normalized, machine-readable Cloudflare deployment target, so `api.cloudflare.com` is not hardcoded into the allowlist. A later task must first add and audit that target record.

The guest image must be built offline from a checksum-verified Ubuntu 24.04 qcow2 using `virt-customize`; the host prerequisite for that operation is committed separately. Neither guest may receive temporary access to Ubuntu package mirrors.

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
