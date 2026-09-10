# Changelog

This file records user-visible changes to landrun. Security-boundary, policy
semantics, and minimum Landlock ABI changes are called out explicitly.

## [Unreleased]

## [0.1.18] - 2026-09-10

### Security

- File descriptors 3 and above are now closed on execution unless explicitly
  requested with a validated `--preserve-fd` option. Standard input, output,
  and error remain inherited.
- Commands are resolved once, opened before policy application, and executed
  from that descriptor. This closes command-path replacement races. Direct
  shebang targets now fail closed; invoke a trusted interpreter explicitly and
  grant it execute access plus read access to the script.
- `--ldd` dependency discovery no longer executes `ldconfig` or another helper
  before entering the sandbox. ELF dependency lookup supports standard Intel
  and ARM multilib layouts and fails closed for unsupported or ambiguous ABIs.
- Explicitly requested controls can no longer be silently discarded by
  `--best-effort` or a matching `--unrestricted-*` option.
- TCP port values are validated before conversion, and duplicate paths and
  ports are normalized for deterministic policy construction.

### Added

- Added strict, versioned JSON policy files via `--policy`. Version 1 maps to
  the existing CLI policy contract and composes additively with explicit flags;
  unknown, duplicate, null, oversized, and unsupported input is rejected.
- Added `--probe` and `--probe-json` for inspecting the running kernel's
  Landlock ABI.
- Added effective-policy reporting to debug output, including the kernel ABI,
  selected policy ABI, handled rights and scopes, audit flags, and TSYNC state.
- Added strict feature-boundary checks for audit-log controls, IPC scoping, and
  pathname UNIX-socket policy handling.
- Added practical usage and audit-logging guides, a security review, hardening
  roadmap, private vulnerability-reporting policy, and pinned ABI compatibility
  documentation.

### Changed

- Launcher and policy-validation failures use exit status 125 so they are
  distinguishable from the sandboxed command's exit status.
- Public-network smoke tests are opt-in; the default integration suite uses
  deterministic local peers.
- CI now tests amd64 and arm64 static builds, minimum and stable Go versions,
  race detection, security-oriented linting, vulnerability scanning, and
  pinned Landlock ABI 4, 6, 9, and 10 kernels.
- The maximum public policy ABI and exact handled-access sets are now explicit
  compatibility contracts, preventing dependency upgrades from silently
  enabling new access-right families.
- CI artifacts now carry verified Go build metadata, and `landrun --version`
  reports the exact source revision and Go toolchain embedded in the binary.
- Added a signed-tag release pipeline for tested amd64 and arm64 artifacts,
  SHA-256 manifests, SPDX SBOMs, and GitHub/Sigstore attestations.
- Protected `v*` release tags with separate owner-only creation and no-bypass
  immutability rulesets; the release gate verifies their visible enforcement,
  pattern, and rule types before it builds.

### Landlock compatibility

- The default strict policy continues to require Landlock ABI 9. Use
  `--best-effort` to run on older kernels, but a control explicitly requested by
  the caller still fails when its minimum ABI is unavailable.
- TCP restrictions require ABI 4, device IOCTL restriction requires ABI 5, IPC
  scoping requires ABI 6, audit configuration requires ABI 7, and pathname
  UNIX-socket controls require ABI 9.
- The dependency understands ABI 10, but landrun does not yet expose UDP policy
  controls; UDP traffic remains unrestricted by Landlock.

## [0.1.17] - 2026-07-22

### Changed

- Upgraded to `go-landlock` v0.9.0 and added Landlock ABI 9 support, including
  pathname UNIX-socket access control.

[Unreleased]: https://github.com/Darkflib/landrun/compare/v0.1.18...HEAD
[0.1.18]: https://github.com/Darkflib/landrun/tree/v0.1.18
[0.1.17]: https://github.com/Darkflib/landrun/tree/v0.1.17
