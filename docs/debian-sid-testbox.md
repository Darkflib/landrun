# Debian sid test box

The [Landlock ABI matrix](abi-testing.md) runs landrun against four pinned UML
kernels built from source. That covers the feature boundaries deterministically,
but every kernel in it is a controlled artifact: a minimal UML build, an exact
commit, and a guest init written for the test harness.

A Debian unstable box covers what the matrix deliberately does not. It runs a
distribution kernel with a distribution LSM configuration, a current glibc, and
a real init on a real virtual machine. It answers a different question: does
landrun still behave when the surrounding userland moves, rather than when the
kernel ABI does.

It is a disposable box. Nothing in CI depends on it, and no result from it is
authoritative for a release. Use it to find surprises early, then reproduce
anything it turns up as a pinned test in the matrix.

## Provisioning

Create a Scaleway Instance from a Debian stable image and paste
[`ci/debian-sid-cloudinit.yaml`](../ci/debian-sid-cloudinit.yaml) into the
cloud-init field. Give it at least 20 GB; the conversion pulls roughly 1.5 GB of
packages once the build toolchain is included.

The conversion runs detached from cloud-init, so `cloud-init status --wait`
returns long before it finishes. Watch it instead through:

```bash
tail -f /var/log/stable-to-sid.log
```

`/var/lib/stable-to-sid.state` records the outcome as `ok`, `hold`, or `fail`.

## What the conversion does

It replaces the stable apt sources with a single `unstable` deb822 stanza —
sid has no `-security` or `-updates` suite — and moves every pre-existing source
aside to `.disabled`, keeping a copy under `/root/apt-backup`. Scaleway's own
repository entries are included in that, because they point at stable and would
otherwise break dependency resolution.

The archive keyring is refreshed while the box is still on stable. Sid's
`Release` file is signed with the next release cycle's automatic signing key,
which a sufficiently old keyring will not carry. If that still fails, the script
falls back to an insecure-transport bootstrap over HTTPS and then re-verifies.

The upgrade itself follows the order the release notes prescribe: `upgrade
--without-new-pkgs`, then `full-upgrade`, then `autoremove`, all with
`--force-confold` so the image's own configuration survives.

Landlock is compiled into Debian kernels but only registers if it appears in the
active LSM list. The script reads `/sys/kernel/security/lsm` and, if `landlock`
is absent, prepends it to whatever is already live rather than substituting a
list of its own, so AppArmor and the other active modules are not dropped. On a
current Debian cloud kernel this is already a no-op.

## The pre-reboot gate

A stable-to-sid jump replaces systemd, dbus, glibc, grub, and openssh in one
transaction. systemd and dbus are torn out from underneath the upgrade while it
runs, so unit enablement in that window can fail silently — the logs show
`Failed to connect to system scope bus` and `Reload daemon failed: Transport
endpoint is not connected` while packages continue to configure successfully.

The reboot is therefore gated. Before rebooting, the script checks that:

- `sshd -t` parses the existing `sshd_config` under the new openssh. The config
  is kept at the old version by `--force-confold`, and a directive retired
  between the stable and sid openssh makes sshd refuse to start.
- `ssh.service` or `ssh.socket` is enabled for the next boot.
- A kernel image, a matching initrd, and a grub.cfg referencing a kernel exist.
- Every `net.ifnames=`, `biosdevname=`, and `console=` token from the running
  `/proc/cmdline` survives into the regenerated grub.cfg.
- Every network interface present before the upgrade is still present.

If any check fails the script writes `hold` and **does not reboot**. The box
stays on sid and stays reachable, which is the only state from which the problem
can be diagnosed cheaply. Fix it, then:

```bash
touch /var/lib/stable-to-sid.done && systemctl reboot
```

## Known upgrade hazards

Two problems observed converting a trixie image on 2026-09-10, both now guarded:

**grub 2.14 drops `/etc/default/grub.d`.** The upgrade logs `cannot delete old
directory '/etc/default/grub.d': Directory not empty`. On a cloud image that
directory is where `console=ttyS0` and `net.ifnames=0` live. Losing
`net.ifnames=0` renames the NIC, which strands a box whose network configuration
names the old interface. The script folds those files into `/etc/default/grub`
and pins the tokens explicitly before the upgrade, then verifies them in the
gate.

**cloud-init stalls in the pre-network local stage.** After the reboot the
console sits on `Job cloud-init-local.service/start running (3min 59s / no
limit)` before eventually proceeding. That stage is datasource discovery: the
sid cloud-init re-asks its debconf question, and answering non-interactively
takes the full default probe list, so it works through datasources that will
never answer. Three guards apply. The script reads the datasource actually in
use from `/var/lib/cloud/instance/datasource` and pins that one in
`/etc/cloud/cloud.cfg.d/99-datasource.cfg`; for the network-metadata
datasources it also bounds `max_wait`, `timeout`, and `retries`; and it adds a
`TimeoutStartSec=120` drop-in for `cloud-init-local.service`, which ships with
no start timeout at all. The unit failing is recoverable, whereas a boot that
hangs on it is not distinguishable from a dead machine.

Note that the stall is not a networking fault and the interface is not renamed —
a Scaleway instance comes up on `ens2` before and after. The grub guard above is
insurance against a different failure, not the cause of this one.

The journal is also made persistent before the upgrade, so a boot that does fail
leaves evidence behind.

## Recovery

If the box does not come back, use the Scaleway serial console rather than
assuming it is dead — a long `cloud-init-local.service` stall looks identical to
a hang from outside. Both the old and the new kernel remain in the grub menu, so
booting the previous kernel is available from the console if the new one is at
fault.

Scaleway rescue mode, or attaching the volume to a second instance, is the
reliable path when the console is not usable. For a disposable test box,
re-provisioning is usually faster than repairing.

## Running the checks

The box carries a Go toolchain and build tooling. Build and run the normal
suites against the sid kernel:

```bash
go build -o landrun ./cmd/landrun && ./landrun --probe-json
```

`ci/test-abi-boundary.sh` takes the expected ABI as its argument, so run it with
whatever the probe reports rather than assuming. The same effective-policy
assertions the matrix makes then apply here. Anything that fails on this box and
not in the matrix is a userland or distribution-configuration difference, and is
worth pinning as a matrix case before it reaches a release.

Once the box is converted, take a Scaleway snapshot. It saves repeating the
conversion on every subsequent spin-up, and it pins the exact sid state a result
was observed against, which matters because sid moves underneath you. The apt
timers and `unattended-upgrades` are disabled by the conversion for that reason.
