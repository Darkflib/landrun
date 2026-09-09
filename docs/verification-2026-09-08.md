# Verification pass, 2026-09-08

Independent check of the hardening work landed by #1 through #4, covering the
security review, the roadmap, the merged pull requests and their review threads,
and the CI workflows.

Verified at: `28d1a11` (merge of #4).

This document exists so the work can be picked up without re-deriving the
analysis. Items are grouped by where the fix belongs and ordered by value within
each group. Every claim below was checked against the tree at `28d1a11`; where a
claim is about behaviour rather than text, the file and line are given.

## What was confirmed correct

Not everything needs work. The following were checked and hold:

- LL-001 is genuinely remediated. `unix.CloseRange(3, UINT_MAX,
  CLOSE_RANGE_CLOEXEC)` in `internal/exec/fds_linux.go`, with `--preserve-fd`
  validated and deduplicated before the range call, and standard streams left
  alone.
- LL-002 is genuinely remediated. No `os/exec` usage remains on any non-test
  path; the only import is `os/exec.LookPath` in `cmd/landrun/main.go`, which
  does not execute anything.
- Every Milestone 0 checkbox is backed by a real workflow step. Actions are
  SHA-pinned with version comments, `permissions: contents: read` is set at the
  top level of all three workflows, and the offline suite does run against the
  exact binary that is later checksummed and uploaded.
- `gofmt -l .` is clean, `GOOS=linux go vet ./...` is clean, and all five
  packages compile for `linux/amd64` including their test binaries.
- The narrowing of ELF support to Intel and ARM in #4 is a defensible call and
  is correctly implemented, including the `e_flags` read from the already-open
  descriptor.

## Open items

### A. Silent discard of explicitly requested rules

**A1 — `--unrestricted-*` discards rules from the same domain without failing.**
`internal/sandbox/sandbox.go:206-244`. When `--unrestricted-filesystem` is set,
every `--ro`, `--rw`, `--rox` and `--rwx` rule is dropped with no diagnostic at
all; `--unix` gets a single `log.Info` line, which is invisible at the default
`--log-level error`. When `--unrestricted-network` is set, `--bind-tcp` and
`--connect-tcp` are dropped with no diagnostic. landrun exits 0 in every case.

`landrun --unrestricted-network --connect-tcp 443 -- cmd` therefore reports
success having enforced nothing that was asked for. This is the same class as
LL-004 and it violates the roadmap principle "never report success when an
explicitly requested control was dropped". It is also considerably cheaper to
fix than LL-004, because no ABI negotiation is involved: the conflict is visible
purely from the parsed flags.

Recorded as LL-005 in the security review. Suggested behaviour: treat a rule
flag combined with the matching `--unrestricted-*` flag as a configuration
error and refuse to start. This pairs naturally with the policy-validation work
already in flight.

### B. Integration suite gives false assurance

**B1 — resolved in the ABI and integration hardening follow-up.** The suite now
uses the artifact's `--probe-json`, applies best-effort only below ABI 9, gates
ABI 9 pathname-UNIX tests, and exercises a real local socket in both allowed and
denied directions. Explicit ABI requirements are rejected by the launcher even
when best-effort is requested.

**B2 — resolved in the ABI and integration hardening follow-up.** The suite no
longer invokes `go run` or depends on a module cache for ABI discovery. A failed
artifact probe is a setup failure, and cannot invert the strict-ABI assertion.

**B3 — the suite is unlintable and unlinted.** `test.sh` is 20 KB of bash that
encodes the policy assertions, and CI checks it with `bash -n` only. Adding
`shellcheck` would be cheap. `actionlint` on the workflows likewise — it is
already clean today, so it would land green.

### C. Documentation accuracy

**C1 — `--ldd` architecture boundary is undocumented.** The README limitation at
line 370 says `--ldd` fails closed for libraries only reachable through a
non-standard loader cache entry, but does not say that support is now limited to
Intel and ARM, nor that a 32-bit ARM ELF whose `e_flags` carries neither
`EF_ARM_ABI_FLOAT_HARD` nor `EF_ARM_ABI_FLOAT_SOFT` is rejected
(`internal/elfdeps/elfdeps.go:45`, asserted by the `ambiguous ARM float ABI`
case in `TestStandardLibDirsRejectsUnsupportedABIs`).

That check runs per file across the whole dependency chain, so a single
dependency with `flags == 0` fails the entire launch, not just that library. The
scope decision from #4 is recorded only in a pull-request comment.

**C2 — security review provenance.** `Reviewed commit: 811cfff` now sits above
`Status: Remediated` text describing work done at `1987fe5`, `be5f03f` and
`28d1a11`. Each status should name the commit and pull request that closed it.
Addressed in this change.

**C3 — no version bump or changelog.** `Version = "0.1.18"`
(`cmd/landrun/main.go:18`) is unchanged across two behaviour-breaking security
fixes: descriptors 3 and above are now closed by default, and `--ldd` now fails
closed. Anyone running 0.1.18 cannot tell which behaviour they have. Milestone 4
covers the changelog; the version constant is worth moving sooner.

### D. Smaller code observations

None of these are exploitable on their own. They are recorded so they are not
rediscovered.

**D1 — `--preserve-fd` is validated after the sandbox is applied.**
`cmd/landrun/main.go:186` applies the policy, `:189` then validates and applies
the descriptor policy. A pure configuration error (a closed descriptor, or a
value below 3) is only caught once confinement is up, and exits 1 —
indistinguishable from the target command failing. When the policy-validation
work lands, split it: validate the descriptor list early alongside the rest of
the policy, and keep only the `CloseRange` call immediately before `exec`.

**D2 — every slice flag splits on commas.** This is the urfave/cli v3 default
separator, so `--ro /a,/b` is two paths and a path containing a comma cannot be
expressed. Relevant to the "normalize duplicate paths and ports" item.

**D3 — `/etc/ld.so.cache` is granted EXECUTE.**
`internal/elfdeps/elfdeps.go:203` adds it to the set that
`cmd/landrun/main.go` feeds into `ReadOnlyExecutablePaths`, so a pure data file
receives `LANDLOCK_ACCESS_FS_EXECUTE` alongside read. Harmless, but wider than
needed.

**D4 — `armeb` skips the float-ABI check** that little-endian ARM requires
(`internal/elfdeps/elfdeps.go:38-46`). One rule or the other, not both.

**D5 — new kernel floor is undocumented.** `CLOSE_RANGE_CLOEXEC` requires Linux
5.11, so landrun now fails on older kernels even with all three
`--unrestricted-*` flags set. Landlock itself needs 5.13, so there is no
practical regression, but the floor moved for the unrestricted path.

### E. Closed during this pass

- `persist-credentials: false` on all four `actions/checkout` steps, the
  `go-compatibility.yml` trigger scope, and the two README wording threads left
  open on #1 — fixed in #5.
- The fourth open thread on #1, reporting `close_range(2)` as a descriptor
  range, is a false positive: `(2)` is the man-page section, and the surrounding
  text already says "descriptors 3 and above". No change needed.

## Note on the CI compatibility matrix

Hosted runners report Landlock ABI 7. Everything the suite asserts about ABI 8
and 9 is therefore either untested or tested in best-effort mode, where the
rights in question are stripped before the assertion runs. Milestone 2 already
recognises that hosted-runner kernels are not a sufficient matrix; the point
here is narrower — Milestone 0 is marked complete, and its acceptance gate
("every pull request exercises policy behavior") is only met for ABI 7 and
below. The gate is worth restating with that bound so a green tick is not read
as broader than it is.
