# Hardening roadmap

This roadmap turns the findings in [the security review](docs/security-review.md)
into measurable implementation and release gates. A follow-up
[verification pass](docs/verification-2026-09-08.md) records what was confirmed
at `28d1a11` and what remains open. Security fixes should remain small,
reviewable, and fail closed when an explicitly requested control cannot be
enforced.

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

That gate is now backed by the pinned UML matrix for ABIs 4, 6, 9, and 10 in
addition to the hosted-runner integration suite.

## Milestone 1: Close policy-boundary issues

Target: next security-focused release.

### Remove pre-sandbox helper execution

- [x] Replace the `ldconfig` subprocess with an in-process cache parser, or remove
  the automatic cache fallback.
- [x] Resolve the target executable once and carry the resolved identity through
  policy creation and `exec`.
- [x] Add hostile-`PATH` and unresolved-SONAME regression tests, and prove that
  `exec` does not re-consult `PATH` after policy construction.
- [x] Carry the resolved executable as a descriptor rather than a path, so the
  file cannot be replaced between policy construction and `execve`.
- [x] Preserve standard multiarch lookup for supported Intel and ARM ELF ABIs,
  and reject other ABIs without reintroducing a helper process.

Acceptance gate: `--ldd` performs no `execve` before Landlock enforcement.

### Define inherited-descriptor behavior

- [x] Default descriptors 3 and above to close-on-exec.
- [x] Add an explicit `--preserve-fd` option if descriptor passing is required.
- [x] Document standard streams and preserved descriptors as capabilities.
- [x] Test regular-file, directory, listening-socket, and connected-socket cases.

Acceptance gate: an unlisted inherited descriptor cannot reach the target
process.

### Validate the policy before applying it

- [x] Reject ports outside their defined range before conversion to `uint16`.
- [x] Define port-zero behavior for bind and connect rules.
- [x] Normalize duplicate paths and ports for deterministic diagnostics.
- [x] Return a distinct launcher/configuration error code rather than conflating it
  with command failure.

Acceptance gate: invalid input cannot silently produce a different policy.

### Make ABI negotiation fail closed for requested controls

- [x] Add `landrun --probe` with human-readable and machine-readable output.
- [x] Compute the minimum ABI required by the selected options.
- [x] Reject unsupported explicitly requested features, including under
  `--best-effort`.
- [x] Print or expose the effective ABI and enforced rights in debug output.
- [x] Add ABI-boundary tests for filesystem truncation, TCP, device IOCTL, scopes,
  audit controls, and pathname UNIX sockets.

Acceptance gate: a successful launch proves that every explicit rule was
enforced.

### Fail closed when a domain override discards requested rules

Tracked as LL-005.

- [x] Reject a rule flag combined with the matching `--unrestricted-*` flag instead
  of dropping the rule and exiting 0.
- [x] Cover `--ro`, `--rw`, `--rox`, `--rwx` and `--unix` against
  `--unrestricted-filesystem`, and `--bind-tcp` and `--connect-tcp` against
  `--unrestricted-network`.
- [x] Route the failure through the launcher/configuration error code.

Acceptance gate: no combination of flags starts the target having silently
discarded a rule the caller asked for.

## Milestone 2: Strengthen compatibility and coverage

- [x] Upgrade to the current `go-landlock` release after reviewing its ABI changes.
- [x] Add controlled tests for ABI 4, 6, 9, and the newest supported ABI using VMs
  or dedicated runners; hosted-runner kernel versions are not a sufficient
  compatibility matrix. The pinned UML matrix and update process are documented
  in [ABI testing](docs/abi-testing.md).
- [x] Add regression tests for the findings in the security review. The mapping
  from each finding to its unit, integration, and ABI-boundary coverage is
  recorded in [the security review](docs/security-review.md#regression-coverage).
- [x] Replace network-dependent integration tests with local deterministic peers;
  keep optional external smoke tests separate.
- [x] Stop injecting `--best-effort` into every integration case. Gate the `--unix`
  cases on ABI 9, run them strictly, and make them connect to a real socket in
  both the allowed and the denied direction.
- [x] Make the integration suite fail loudly when the Landlock ABI probe cannot run,
  instead of falling back to 0 and inverting the strict-ABI assertion.
- [x] Drop the suite's `go run` dependency once `landrun --probe` exists, so it can
  run against a downloaded artifact without a Go toolchain.
- [x] Lint the security-relevant surfaces in CI: `shellcheck` on `test.sh` and
  `actionlint` on the workflows.
- [x] Add race testing where it is compatible with the Landlock test harness.
- [x] Record kernel ABI and effective policy in CI output.

Acceptance gate: compatibility behavior is tested at feature boundaries, not
inferred from a single current kernel.

## Milestone 3: Expand supported Landlock controls

- [x] Evaluate ABI 10 UDP bind/connect-send support and its ephemeral-port rules;
  the dependency is upgraded, but UDP controls remain disabled until landrun has
  an explicit, validated policy contract for them.
- [x] Track new filesystem and network access rights without enabling them
  implicitly in existing policy profiles. Exact handled-access sets and the
  maximum public policy ABI are pinned by unit and UML tests; the update process
  is documented in [ABI testing](docs/abi-testing.md#reviewing-new-rights-and-abis).
- Add policy-file support only after the CLI policy contract is stable.
- [x] Add audit-log guidance and diagnostics without requiring privileged
  access. Landrun's effective-policy record reports applied audit flags; the
  operational and host-observability boundary is documented in
  [Landlock audit logging](docs/audit-logging.md).
- [x] Document the `--ldd` support boundary in the README: Intel and ARM only, and
  32-bit ARM objects carrying neither `EF_ARM_ABI_FLOAT_HARD` nor
  `EF_ARM_ABI_FLOAT_SOFT` are rejected, per file across the dependency chain.

Acceptance gate: every new access-right family has strict compatibility
behavior, negative tests, and documented limitations.

## Milestone 4: Release and security process

- [x] Add `SECURITY.md` with a private vulnerability-reporting route and supported
  release policy.
- Publish signed tags, checksums, and a software bill of materials for release
  artifacts.
- Generate artifacts only from protected tags after all required checks pass.
- [x] Document which source revision and Go toolchain produced each artifact.
  CI forces and verifies Go VCS stamping, `landrun --version` reports both
  values, and each artifact bundle includes `landrun.buildinfo`.
- [x] Maintain a changelog that calls out changes to policy semantics and minimum
  ABI requirements.

Acceptance gate: users can verify an artifact and understand its exact security
contract without trusting an unversioned binary.

## Out of scope for Landlock alone

Landrun should not claim to provide complete process or network isolation.
Hostile workloads may additionally require user, mount, PID, and network
namespaces; seccomp; cgroups; and explicit broker/socket isolation. These can be
composed around landrun, but should not be hidden behind flags that Landlock
cannot faithfully implement.
