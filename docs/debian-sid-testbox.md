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
- The entry GRUB will actually boot has its kernel and a same-version initrd on
  disk, and carries every `net.ifnames=`, `biosdevname=`, and `console=` token
  from the running `/proc/cmdline` on *its own* command line. Checking `grub.cfg`
  as a whole is not equivalent: a token present only on a recovery or
  previous-kernel entry would pass while the box boots without it. A
  `GRUB_DEFAULT` other than `0` fails the check rather than being guessed at.
- Every network interface present before the upgrade is still present.

If any check fails the script writes `hold` and **does not reboot**. The box
stays on sid and stays reachable, which is the only state from which the problem
can be diagnosed cheaply. Fix the failure, then re-run the gate rather than
rebooting blind:

```bash
/usr/local/sbin/stable-to-sid recheck
```

`recheck` runs the pre-reboot checks only, and reboots if every one passes. It
recomputes the preserved command-line tokens and the interface list from the
live system, which is still the pre-reboot state, so it validates exactly what
the conversion would have.

Creating the completion marker by hand skips the gate altogether, which is the
one thing the gate exists to stop you doing. Keep it for the case where you have
looked at a failing check and decided the check is wrong:

```bash
touch /var/lib/stable-to-sid.done && systemctl reboot
```

## Known upgrade hazards

Both were seen converting a trixie image on 2026-09-10. Only the second one
actually cost anything; the first is latent, and guarded on principle.

**grub 2.14 drops `/etc/default/grub.d`.** The upgrade logs `cannot delete old
directory '/etc/default/grub.d': Directory not empty`. On cloud images that
directory is where `console=` and `net.ifnames=0` settings live, and losing
`net.ifnames=0` renames the NIC, which strands a box whose network configuration
names the old interface.

That did not happen here. A Scaleway trixie image uses predictable naming and
comes up on `ens2` either way, so the gate found only `console=` tokens to
preserve and the guard was a no-op. It is kept because the failure it prevents
is unrecoverable without console access, and the cost of carrying it is a
concatenated file. The script folds `/etc/default/grub.d/*.cfg` into
`/etc/default/grub` and pins the tokens explicitly before the upgrade, then
verifies they survived into the regenerated `grub.cfg`.

**cloud-init stalls the boot after the upgrade.** The console sits on `Job
cloud-init-local.service/start running (3min 59s / no limit)` before eventually
proceeding.

Pinning the datasource does not fix this. It was the obvious first theory — the
sid cloud-init re-asks its debconf question, and answering non-interactively
takes the full default probe list — but a run with the active datasource pinned
in `/etc/cloud/cloud.cfg.d/99-datasource.cfg` and its metadata wait bounded
stalled in exactly the same place. The cause is inside cloud-init 26.x, which
now drives its stages against a `cloud-init-main.service` single process, not in
the datasource list. The pin is kept because it is harmless and removes one
variable, but it is not the remedy.

Two things actually contain it. Every cloud-init stage unit gets a
`TimeoutStartSec=120` drop-in, because they ship with no start timeout at all;
bounding only the local stage is not enough, since the stall simply reappears in
`cloud-init-network.service`. And once the conversion is finished, cloud-init is
disabled outright through `/etc/cloud/cloud-init.disabled`. It has nothing left
to do on this box, and leaving it enabled makes every boot depend on a package
that sid keeps moving.

A stage timing out is recoverable; a boot that hangs is indistinguishable from a
dead machine from the outside. SSH still comes up in the timed-out case, because
the keys were written to disk on the first boot and cloud-init failing later
does not remove them.

Note that the stall is not a networking fault and the interface is not renamed —
a Scaleway instance comes up on `ens2` before and after, and systemd-networkd
brings the network up normally once the failed stage is out of the way. The grub
guard above is insurance against a different failure, not the cause of this one.

The journal is also made persistent before the upgrade, so a boot that does fail
leaves evidence behind.

## Recovery

If the box does not come back, use the Scaleway serial console rather than
assuming it is dead — a long `cloud-init-local.service` stall looks identical to
a hang from outside. Both the old and the new kernel remain in the grub menu, so
booting the previous kernel is available from the console if the new one is at
fault.

The console is only useful if you can log in on it, and cloud images ship with
root locked. Set `ROOT_PASSWORD_HASH` in the cloud-init before provisioning:

```bash
openssl passwd -6
```

Paste the result between the single quotes in the knobs block. It has to be
single quotes — a crypt hash is full of `$`, and inside double quotes the shell
eats it silently, leaving an empty value and a locked account. The password is
applied before anything else the script does, so it survives every later
failure, and it is used for the serial and emergency console only. SSH password
authentication is never enabled.

Use a throwaway password. The script is written `0700` and the conversion also
tightens cloud-init's own copies of the user-data, but neither of those contains
the hash: the instance metadata service serves user-data back to any process on
the box, so an unprivileged local user can read it whatever the file modes say.
That is inherent to putting a secret in cloud-init user-data rather than
something this file can fix, so do not reuse a password from anywhere else.

Leaving the hash empty is a supported choice, and the script says so loudly in
the log rather than failing. It just means the console is decorative.

Scaleway rescue mode, or attaching the volume to a second instance, is the
reliable path when the console is not usable. For a disposable test box,
re-provisioning is usually faster than repairing.

## Running the checks

The box carries a Go toolchain and build tooling. Build the way CI does, so the
result is comparable to the matrix:

```bash
CGO_ENABLED=0 go build -trimpath -o landrun ./cmd/landrun && ./landrun --probe-json
```

Set `CGO_ENABLED` explicitly. The build, release, and ABI matrix workflows all
pin it to `0`, but a plain `go build` on this box defaults to `1` because a C
toolchain is present, and that is not the same binary. `libcap/psx` compiles its
pure-Go path under `CGO_ENABLED=0` and its C path under `CGO_ENABLED=1`, and
those are different mechanisms for applying a syscall across every thread — the
behavior the effective-policy record reports as `thread_synchronized`.

That makes the cgo build worth running here deliberately, as a second pass, and
not by accident as the first one. No CI job builds it, so this box is the only
place it gets exercised:

```bash
CGO_ENABLED=1 go build -trimpath -o landrun-cgo ./cmd/landrun && ./landrun-cgo --probe-json
```

A divergence between the two on the same kernel is a finding about landrun, not
about sid, and belongs in the matrix rather than here.

`ci/test-abi-boundary.sh` takes the expected ABI as its argument and accepts
only `4`, `6`, `9`, or `10`, the boundaries it has cases for. Pass what the probe
reported, provided it is one of those. A probe reporting anything else is itself
the finding rather than a value to pass in: the harness needs a boundary case for
the new ABI first, and landrun needs the policy-contract review in
[abi-testing.md](abi-testing.md#reviewing-new-rights-and-abis) before it exposes
anything new. It also expects the binary at
`./landrun`, and it assumes that binary is **static**: it sandboxes landrun with
itself using `--rox ./landrun` alone, which is a sufficient policy only when
there is no loader and no shared object to map. Pointed at a `CGO_ENABLED=1`
build the script fails at its first policy step with `failed to execute command:
permission denied`, because the dynamic loader and libc need the execute right
and nothing granted it. That is Landlock behaving correctly, not a regression.
CI only ever builds static, so the assumption is safe there; just do not read
that failure as a finding.

To exercise a dynamic build, use landrun's own resolver rather than hand-written
path grants:

```bash
./landrun-cgo --best-effort --add-exec --ldd -- ./landrun-cgo --probe-json
```

`--ldd` walks the ELF dependency graph, which makes it the interesting thing to
run here: it is the part of landrun most exposed to a moving libc and a changing
loader layout.

## Results so far

Recorded so the next run has something to compare against, not as a guarantee.

On 2026-09-10, kernel `7.1.13+deb14-cloud-amd64` with glibc 2.43-5:

- The probe reported ABI 9, matching the `Linux 7.1.y` row in the matrix.
- `ci/test-abi-boundary.sh 9` passed in full against the static build.
- The `CGO_ENABLED=0` and `CGO_ENABLED=1` builds produced byte-identical
  effective-policy records, `thread_synchronized: true` in both. The psx code
  path does not change the policy landrun applies on this kernel.
- `--add-exec --ldd` resolved correctly against the sid loader layout,
  granting `/etc/ld.so.cache`, `libc.so.6`, the named shared objects, and
  `/lib64/ld-linux-x86-64.so.2`.

No regressions found.

Anything that fails here but not in the matrix is a userland or
distribution-configuration difference. Reproduce it as a pinned matrix case
before it reaches a release rather than treating this box as the evidence.

## Snapshotting

Once the box is converted, take a Scaleway snapshot. It saves repeating the
conversion on every subsequent spin-up, and it pins the exact sid state a result
was observed against, which matters because sid moves underneath you. The apt
timers and `unattended-upgrades` are disabled by the conversion for that reason.

One consequence to know about before you snapshot: the conversion disables
cloud-init, so an instance created from that snapshot will not have keys
injected into it. The `authorized_keys` written on the original box's first boot
is baked into the snapshot and keeps working, so this is invisible as long as
you use the same key. If you need key injection on snapshot-derived instances,
set `DISABLE_CLOUD_INIT_AFTER=0` and accept the boot stall, or delete
`/etc/cloud/cloud-init.disabled` before taking the snapshot.
