# Usage guide

Landrun is most useful as a small, application-specific access-control layer.
Start with the narrowest useful policy, run the real workload, and add only the
paths, TCP ports, UNIX sockets, and environment variables it actually needs.

The examples below are starting points, not universal profiles. Library,
certificate, name-service, and runtime-data paths vary between distributions.
Use absolute command paths in long-lived policies and review every broad
directory grant such as `--rox /usr`.

## Check the host first

Query the kernel's Landlock ABI before choosing features:

```bash
landrun --probe
landrun --probe-json
```

Landrun targets ABI 9 in strict mode. Add `--best-effort` when a policy may run
on an older kernel. Best-effort mode can omit unrequested protections introduced
by newer ABIs, but landrun still fails with status 125 if the host cannot enforce
an explicitly requested control.

## Practical recipes

### Read one file with a dynamically linked tool

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro "$PWD/input.json" \
    -- \
    /usr/bin/jq . "$PWD/input.json"
```

`--add-exec` grants execute access to the resolved command. `--ldd` recursively
grants execute access to the ELF interpreter and dependency graph named in ELF
metadata. It does not discover plugins or libraries loaded later with
`dlopen(3)`; grant those paths explicitly.

The in-process dependency resolver supports standard Intel and ARM ELF ABIs and
multilib directories. Other ELF machine types fail closed. For 32-bit ARM, each
object in the dependency chain must declare either the hard-float or soft-float
ABI flag; ambiguous objects are rejected. Non-standard dynamic-loader cache
entries may also need explicit `--rox` rules.

Landrun opens the resolved command before applying Landlock and executes that
descriptor with `execveat(2)`. This prevents a writable directory or another
actor from replacing the command between policy construction and launch.
Direct shebang scripts are rejected: the kernel requires their command
descriptor to remain open for the interpreter, which would turn an internal
descriptor into an unlisted capability. Invoke a trusted interpreter
explicitly, grant its path with `--rox`, and grant the script read access.

### Work in one writable directory

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro "$PWD/config.toml" \
    --rw "$PWD/data" \
    -- \
    /opt/myapp/bin/myapp --config "$PWD/config.toml"
```

Use `--rw`, not `--rwx`, unless the workload genuinely needs to execute files
from the writable tree. Keeping writable and executable trees separate reduces
what an exploited process can replace and then run.

### Run a build or test job

Build tools normally execute many programs and write caches and temporary
files, so their profiles are broader:

```bash
landrun \
    --best-effort \
    --rox /usr \
    --ro /etc \
    --rwx "$PWD" \
    --rw /tmp \
    --unrestricted-network \
    --env PATH \
    --env HOME="$PWD/.landrun-home" \
    -- \
    /usr/bin/make test
```

Create `.landrun-home` before starting the job. Remove
`--unrestricted-network` when the build is known to be offline, or replace it
with the specific outbound TCP ports it requires. A build that downloads and
executes dependencies remains exposed to supply-chain risk; Landlock only
limits the access available after compromise.

### Allow an HTTPS client

```bash
landrun \
    --best-effort \
    --add-exec \
    --rox /usr/lib \
    --ro /etc/ssl/certs,/etc/resolv.conf,/etc/nsswitch.conf,/etc/hosts \
    --connect-tcp 443 \
    -- \
    /usr/bin/curl https://example.com/
```

Adjust the library, CA-certificate, and name-service paths for the host. The
TCP rule permits connections to destination port 443 at **any** address; it is
not a hostname or destination-IP allowlist. This landrun version does not
restrict UDP, so DNS and other UDP traffic need a network namespace, firewall,
or service/network policy when they are part of the threat model.

### Run a TCP service

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro /etc/myapp,/etc/ssl/certs \
    --rw /var/lib/myapp \
    --bind-tcp 8080 \
    -- \
    /opt/myapp/bin/server
```

`--bind-tcp 8080` controls the local TCP port. It does not decide which remote
clients may connect; use a firewall or network policy for that. Landrun cannot
grant permission that Unix credentials, capabilities, another LSM, or an outer
container has denied.

### Connect to a pathname UNIX socket

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro /etc/postgresql \
    --unix /run/postgresql/.s.PGSQL.5432 \
    -- \
    /usr/bin/psql mydb
```

This requires ABI 9. Because `--unix` is explicit, landrun fails rather than
silently dropping it on an older kernel. Abstract UNIX sockets are controlled
separately by IPC scoping; `--unrestricted-scoped` relaxes that protection and
signal scoping together.

### Pass an existing descriptor deliberately

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --preserve-fd 3 \
    -- \
    /bin/sh -c 'IFS= read -r line <&3; printf "%s\n" "$line"' \
    3<./input.txt
```

Descriptors are capabilities. A preserved file, directory, or socket remains
usable even if the Landlock policy would prevent opening it by path or creating
the connection. Landrun closes descriptors 3 and above by default.

## How Landlock composes with other controls

Landlock is a stackable Linux Security Module. Its rules add restrictions to
the process's existing Unix permissions and other LSM policies; they never grant
access. A process can add another Landlock layer, but cannot remove an inherited
one. The policy is inherited by descendants.

| Control | Primary job | What Landrun does not replace |
| --- | --- | --- |
| Unix users, groups, modes, and ACLs | Establish the process's ordinary identity and host permissions | Run the workload as a dedicated, non-root identity first |
| SELinux, AppArmor, or another system LSM | Enforce administrator-owned, system-wide mandatory policy | Landlock is application-owned and stacks with these policies |
| Capabilities and `no_new_privs` | Limit privileged kernel operations and privilege gained through `execve` | Landrun sets `no_new_privs` when it applies a ruleset, but it does not choose a UID or drop an already-held capability set |
| Seccomp | Restrict the syscall surface | Landlock controls access to kernel objects, not the general set of syscalls |
| User, mount, PID, IPC, and network namespaces | Give the workload isolated views of system resources | Landrun does not create namespaces |
| cgroups and service-manager limits | Bound memory, CPU, process count, and I/O | Landrun does not provide resource limits or availability protection |
| Firewall, network namespace, or orchestrator network policy | Control peers, addresses, protocols, and packet flow | Landrun's exposed network policy is TCP-port based; UDP is currently unrestricted |
| Container runtime | Combine filesystem images, namespaces, capabilities, seccomp, cgroups, and lifecycle management | Landrun is not a container runtime, though it can add a final in-process restriction inside one |

The effective permission is the intersection of all these layers. An outer
layer must allow landrun to read the paths used to construct its ruleset and to
call the Landlock syscalls. If a seccomp profile blocks
`landlock_create_ruleset(2)`, `landlock_add_rule(2)`, or
`landlock_restrict_self(2)`, landrun fails during setup rather than creating the
requested sandbox.

### With systemd

Use systemd for service identity, capabilities, namespace/mount hardening,
resource limits, and lifecycle management; use landrun for the service-specific
filesystem, TCP-port, and UNIX-socket policy:

```ini
[Service]
Type=simple
User=myapp
Group=myapp
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/myapp
MemoryMax=512M
TasksMax=128
ExecStart=/usr/local/bin/landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro /etc/myapp,/etc/ssl/certs \
    --rw /var/lib/myapp \
    --bind-tcp 8080 \
    -- \
    /opt/myapp/bin/server
```

Add `SystemCallFilter=` only after verifying that the allowlist includes the
three Landlock syscalls used during launcher setup. If the service binds a port
below 1024, decide explicitly whether to retain `CAP_NET_BIND_SERVICE` or have
an unprivileged outer proxy own the low port.

### With Podman or Kubernetes

Prefer a rootless/non-root container, a read-only root filesystem, dropped
capabilities, `no-new-privileges`/`allowPrivilegeEscalation: false`, a seccomp
profile, resource limits, and an isolated container network. Landrun can then be
the container entrypoint (or wrap it) to reduce access further inside the
container's already-isolated view.

For example, an offline Podman job can combine an outer container boundary with
an inner application policy:

```bash
podman run --rm \
    --read-only \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --pids-limit=128 \
    --memory=512m \
    --network=none \
    --volume "$PWD/data:/data:rw,Z" \
    example/myjob:latest \
    landrun --best-effort --add-exec --ldd --rw /data -- \
    /usr/local/bin/myjob
```

Pin production images by digest. The volume label suffix is appropriate for an
SELinux host but may need adjustment elsewhere. Because the outer container has
`--network=none`, an inner Landrun TCP allowance could not restore networking.
Kubernetes has analogous `securityContext` fields for a non-root identity,
`allowPrivilegeEscalation: false`, dropped capabilities, a read-only root
filesystem, and seccomp; resource limits and NetworkPolicy cover separate
boundaries.

This only works when the container's kernel and seccomp profile expose the
Landlock syscalls. Test `landrun --probe` in the deployed container image; do
not infer support from the build host. Avoid privileged or host-namespace modes,
which substantially weaken the outer isolation that Landrun is meant to
complement.

## Troubleshooting a policy

1. Run `landrun --probe` on the actual execution host or inside the container.
2. Use an absolute command path and add `--add-exec`.
3. Start with `--ldd`, then add paths for runtime-loaded plugins, locale data,
   certificates, name-service files, configuration, state, and temporary data.
4. Use `--log-level debug` to inspect the normalized policy and effective ABI.
5. On ABI 7+ hosts, use Landlock audit records when the system has auditing
   enabled. The kernel documentation describes the `fs.*`, `net.*`, and scope
   blockers emitted for denials.
6. Treat exit status 125 as a launcher or policy-setup failure. Other exit
   statuses come from the executed command.

Do not debug by permanently broadening a rule to `/`. Once the missing access
is identified, grant the smallest stable path or port that represents it.

## Further reading

- [Linux kernel Landlock userspace API](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
- [Linux kernel Landlock system-wide management](https://www.kernel.org/doc/html/latest/admin-guide/LSM/landlock.html)
- [systemd execution environment](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Podman run reference](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [Kubernetes Linux kernel security constraints](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/)
