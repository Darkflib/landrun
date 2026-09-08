# Hardening roadmap

This roadmap turns the findings in [the security review](docs/security-review.md)
into measurable implementation and release gates. Security fixes should remain
small, reviewable, and fail closed when an explicitly requested control cannot
be enforced.

## Principles

- Do not execute target- or environment-controlled code before confinement.
- Treat inherited file descriptors as explicit capabilities.
- Reject invalid policy input instead of coercing it.
- Never report success when an explicitly requested control was dropped.
- Make the effective kernel ABI and policy inspectable.
- Preserve the single static binary and unprivileged execution model.

## Milestone 0: Establish a trustworthy CI baseline

Status: complete.

- [x] Run unit tests with the minimum supported Go release and stable Go.
- [x] Test on amd64 and arm64 Linux runners.
- [x] Run `go vet`, `gofmt`, module-tidiness, and module-verification checks.
- [x] Run the offline integration suite against the exact artifact being
  uploaded.
- [x] Build with `CGO_ENABLED=0` and verify that the artifact is statically
  linked.
- [x] Publish a SHA-256 checksum alongside each artifact.
- [x] Run a pinned `govulncheck` on pushes, pull requests, and a weekly
  schedule.

Acceptance gate: every pull request exercises policy behavior rather than only
proving that the source compiles.

## Milestone 1: Close policy-boundary issues

Target: next security-focused release.

### Remove pre-sandbox helper execution

- [x] Replace the `ldconfig` subprocess with an in-process cache parser, or remove
  the automatic cache fallback.
- [x] Resolve the target executable once and carry the resolved identity through
  policy creation and `exec`.
- [x] Add hostile-`PATH`, unresolved-SONAME, and executable-replacement regression
  tests.

Acceptance gate: `--ldd` performs no `execve` before Landlock enforcement.

### Define inherited-descriptor behavior

- [x] Default descriptors 3 and above to close-on-exec.
- [x] Add an explicit `--preserve-fd` option if descriptor passing is required.
- [x] Document standard streams and preserved descriptors as capabilities.
- [x] Test regular-file, directory, listening-socket, and connected-socket cases.

Acceptance gate: an unlisted inherited descriptor cannot reach the target
process.

### Validate the policy before applying it

- Reject ports outside their defined range before conversion to `uint16`.
- Define port-zero behavior for bind and connect rules.
- Normalize duplicate paths and ports for deterministic diagnostics.
- Return a distinct launcher/configuration error code rather than conflating it
  with command failure.

Acceptance gate: invalid input cannot silently produce a different policy.

### Make ABI negotiation fail closed for requested controls

- Add `landrun --probe` with human-readable and machine-readable output.
- Compute the minimum ABI required by the selected options.
- Reject unsupported explicitly requested features, including under
  `--best-effort`.
- Print or expose the effective ABI and enforced rights in debug output.
- Add ABI-boundary tests for filesystem truncation, TCP, device IOCTL, scopes,
  audit controls, and pathname UNIX sockets.

Acceptance gate: a successful launch proves that every explicit rule was
enforced.

## Milestone 2: Strengthen compatibility and coverage

- Upgrade to the current `go-landlock` release after reviewing its ABI changes.
- Add controlled tests for ABI 4, 6, 9, and the newest supported ABI using VMs
  or dedicated runners; hosted-runner kernel versions are not a sufficient
  compatibility matrix.
- Add regression tests for the findings in the security review.
- Replace network-dependent integration tests with local deterministic peers;
  keep optional external smoke tests separate.
- Add race testing where it is compatible with the Landlock test harness.
- Record kernel ABI and effective policy in CI output.

Acceptance gate: compatibility behavior is tested at feature boundaries, not
inferred from a single current kernel.

## Milestone 3: Expand supported Landlock controls

- Evaluate ABI 10 UDP bind/connect-send support and its ephemeral-port rules.
- Track new filesystem and network access rights without enabling them
  implicitly in existing policy profiles.
- Add policy-file support only after the CLI policy contract is stable.
- Add audit-log guidance and diagnostics without requiring privileged access.

Acceptance gate: every new access-right family has strict compatibility
behavior, negative tests, and documented limitations.

## Milestone 4: Release and security process

- Add `SECURITY.md` with a private vulnerability-reporting route and supported
  release policy.
- Publish signed tags, checksums, and a software bill of materials for release
  artifacts.
- Generate artifacts only from protected tags after all required checks pass.
- Document which source revision and Go toolchain produced each artifact.
- Maintain a changelog that calls out changes to policy semantics and minimum
  ABI requirements.

Acceptance gate: users can verify an artifact and understand its exact security
contract without trusting an unversioned binary.

## Out of scope for Landlock alone

Landrun should not claim to provide complete process or network isolation.
Hostile workloads may additionally require user, mount, PID, and network
namespaces; seccomp; cgroups; and explicit broker/socket isolation. These can be
composed around landrun, but should not be hidden behind flags that Landlock
cannot faithfully implement.
