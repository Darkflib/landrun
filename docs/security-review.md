# Security review

Status: issues documented here are not fixed unless the entry explicitly says otherwise.

Review date: 2026-09-08
Reviewed commit: `811cfff51ceaf3d9843708aa6d22e9b84ccac8b4`

Remediation status below is tracked past that commit; each entry names the pull
request and commit that closed it. See
[the verification pass](verification-2026-09-08.md) for a follow-up check of
this document, the roadmap, the merged pull requests, and CI at `28d1a11`.

## Scope and threat model

This review examined landrun as a launcher for reducing the impact of buggy or
untrusted Linux processes. It covered policy parsing, work performed before the
Landlock domain is entered, file-descriptor inheritance, ABI negotiation,
filesystem and TCP rule construction, process execution, dependencies, and CI.

Landlock is a stackable access-control mechanism, not a complete container. A
Landlock-only launcher does not provide PID, mount, user, or network namespaces,
seccomp filtering, resource limits, or destination-address filtering.

## Findings

### LL-001: Inherited file descriptors bypass path restrictions

Severity: High for a general-purpose sandbox launcher.

Status: Remediated in #3 (`be5f03f`). Descriptors 3 and above are marked
close-on-exec by default. `--preserve-fd` provides an explicit, validated
opt-in for descriptor passing; standard input, output, and error remain
inherited.

`internal/exec.Run` calls `syscall.Exec` without closing or marking inherited
file descriptors close-on-exec. Landlock does not retroactively restrict files
opened before the policy was enforced. A process can therefore read or modify a
denied file through an inherited descriptor.

This was reproduced by opening a denied file as descriptor 9 in the parent and
reading it successfully from the sandboxed command:

```text
inherited_fd_status=0 output=top-secret-through-fd
```

Recommended remediation:

- Mark descriptors 3 and above close-on-exec by default, preferably with
  `close_range(2)` and `CLOSE_RANGE_CLOEXEC`.
- Add an explicit, narrowly validated `--preserve-fd` option for intentional
  descriptor passing.
- Document standard input, output, and error as capabilities that are always
  inherited.
- Add positive and negative integration tests for inherited regular files,
  directories, and sockets.

### LL-002: `--ldd` may execute an ambient `ldconfig` before confinement

Severity: High impact with an attacker-controlled `PATH` entry.

Status: Remediated in #2 (`1987fe5`), with the supported-ABI boundary
narrowed in #4 (`28d1a11`). Dependency discovery no longer invokes `ldconfig`
or any other helper. Libraries that cannot be resolved from the ELF search
paths and architecture-specific standard directories now cause the launch to
fail. The standard-directory lookup accounts for ELF class, endianness, and
ARM floating point ABI across the supported Intel and ARM targets. Other ELF
ABIs are rejected explicitly rather than searched using guessed directories.

The ELF dependency parser is non-executing, but its cache fallback invokes
`exec.Command("ldconfig", "-p")`. This lookup uses the launcher's ambient
`PATH`, and it happens before `sandbox.Apply`. A malicious ELF can trigger the
fallback with an unresolved `DT_NEEDED` entry. If an attacker can place a fake
`ldconfig` earlier in `PATH`, that program executes outside the sandbox.

The behavior was reproduced with an ELF containing an unresolved dependency
and a marker-writing `ldconfig` placed first in `PATH`.

Recommended remediation:

- Prefer parsing `/etc/ld.so.cache` without spawning a process.
- As an interim measure, execute a verified absolute system path rather than an
  ambient `PATH` lookup.
- Add a regression test that supplies a hostile `PATH` and proves no external
  helper is executed.
- Treat all executable and dependency discovery as part of the security
  boundary and complete it without running target-controlled code.

### LL-003: Out-of-range ports wrap to a different policy

Severity: Medium.

Status: Remediated in this change. Policies are validated before Landlock rules are built.
Bind ports must be in the range 0-65535, with zero explicitly retaining the
kernel's ephemeral-port behavior. Connect ports must be in the range 1-65535.
Ports are converted to `uint16` only after validation, and duplicate paths and
ports are de-duplicated in deterministic order.

CLI ports are parsed as `int` and converted directly to `uint16`. Negative and
greater-than-65535 values therefore wrap rather than fail. For example,
`--connect-tcp 131071` becomes port 65535.

This was reproduced with a local listener:

```text
wrapped_port_status=0 server_accepted=0
```

Both zero exit statuses show that a policy naming 131071 allowed the connection
to 65535.

Recommended remediation:

- Validate every port before building the sandbox configuration.
- Reject negative values and values above 65535.
- Define and test port-zero semantics separately for bind and connect rules.

### LL-004: Best-effort mode can silently discard requested controls

Severity: Medium, rising to High when callers treat successful startup as proof
that every requested restriction is active.

Status: Open.

The default policy targets Landlock ABI 9. On an older kernel, `--best-effort`
downgrades the configuration and may remove access rights explicitly requested
on the command line. The command still starts without reporting the effective
policy.

On a host with Landlock ABI 6, a policy containing `--unix allowed.sock`
successfully connected to a different pathname UNIX socket. ABI 6 cannot
restrict pathname UNIX socket resolution; that access right requires ABI 9.
The same class of problem applies to requested TCP restrictions on kernels
older than ABI 4.

Recommended remediation:

- Derive a minimum ABI from explicitly requested options and fail when it is
  unavailable, even when best-effort mode is selected.
- Limit best-effort degradation to unrequested, additional coverage.
- Add `--probe` and an effective-policy report showing the kernel ABI, selected
  ABI, enforced access rights, and unsupported controls.
- Add tests for every option at one ABI below its introduction.

### LL-005: Domain overrides silently discard rules from the same domain

Severity: Medium, rising to High when callers treat successful startup as proof
that every requested restriction is active.

Status: Open. Found during the 2026-09-08 verification pass, not the original
review.

`--unrestricted-filesystem` discards every `--ro`, `--rw`, `--rox` and `--rwx`
rule with no diagnostic, and `--unix` with only a `log.Info` line that is
invisible at the default `--log-level error`. `--unrestricted-network` discards
`--bind-tcp` and `--connect-tcp` with no diagnostic. landrun exits 0 in every
case, so:

```text
landrun --unrestricted-network --connect-tcp 443 -- cmd
```

reports success having enforced nothing that was requested. The rules are built
inside `if !cfg.UnrestrictedFilesystem` and `if !cfg.UnrestrictedNetwork` blocks
at `internal/sandbox/sandbox.go:206-244`.

This is the same class as LL-004, but it does not involve ABI negotiation: the
conflict is visible from the parsed flags alone, before any kernel interaction.

Recommended remediation:

- Treat a rule flag combined with the matching `--unrestricted-*` flag as a
  configuration error and refuse to start.
- Keep the check in the policy-validation path, so it shares the launcher error
  code with the other input-validation failures.
- Add negative tests for each pairing.

## Platform limitations relevant to the findings

The validation host ran Debian 13 with kernel `6.12.107+deb13-amd64`, Landlock
enabled, and runtime ABI 6. On that host:

- Filesystem rights through ABI 5 are available.
- Classic TCP bind/connect rules are available.
- Abstract UNIX socket and signal scoping are available.
- Pathname UNIX socket restrictions are unavailable.
- UDP restrictions are unavailable to this landrun version.
- Multipath TCP is not governed by Landlock's classic TCP rights.

Processes may also escape the intended effect of path restrictions by asking a
reachable broker service to perform work on their behalf. Pathname UNIX sockets
are especially important for systemd, D-Bus, database, container, and desktop
services.

## Validation results

The review performed the following checks:

- All Go test packages were cross-compiled and passed on the ABI 6 validation
  host.
- The offline integration suite passed against a statically linked amd64
  artifact. The suite injects `--best-effort` into every case, so on an ABI 6
  host it did not exercise the ABI 7 to ABI 9 access rights; see
  [the verification pass](verification-2026-09-08.md) section B1.
- `go vet ./...` passed.
- `govulncheck ./...` reported no known reachable vulnerabilities on the review
  date.
- The binary built successfully with `CGO_ENABLED=0` and was identified as
  statically linked.

Before the accompanying CI changes, the GitHub workflows only compiled the
project; they did not run the unit tests, integration suite, formatting checks,
module reproducibility checks, or vulnerability scan.

## Usage guidance before remediation

Landrun can still provide useful defense in depth when its limitations match the
threat model:

- Use only validated literal port values.
- Do not assume `--best-effort` enforced options unavailable to the host ABI.
- Do not treat the TCP allowlist as a complete network firewall.
- Combine Landlock with namespaces, seccomp, and resource controls for hostile
  workloads.
