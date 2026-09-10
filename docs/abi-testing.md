# Landlock ABI testing

The `Landlock ABI matrix` workflow runs the static amd64 landrun binary inside
four pinned User-Mode Linux (UML) kernels. This tests the kernel interfaces at
the feature boundaries that matter to landrun instead of inferring
compatibility from whichever kernel a hosted runner currently uses.

| Kernel | Expected ABI | Boundary covered |
| --- | ---: | --- |
| Linux 6.7.y | 4 | filesystem truncation and TCP |
| Linux 6.12.y | 6 | device IOCTL and IPC scopes |
| Linux 7.1.y | 9 | pathname UNIX sockets and thread synchronization |
| Linux 7.2.y | 10 | newest dependency-supported ABI, with UDP kept out of landrun's policy |

Both the kernel revisions and the `landlock-test-tools` revision are exact
commit IDs in `.github/workflows/abi-matrix.yml`. The light UML kernels are
built from source, cached by both revisions, and restored with
`fail-on-cache-miss` before testing. Each test job probes the guest kernel and
requires the exact expected ABI before it exercises effective-policy reporting,
strict compatibility failures, explicit audit controls, and the offline
integration suite.

The upstream guest init opportunistically mounts 9p and FUSE fixtures when it
finds their helpers through systemd's guest environment. Landrun does not use
either optional filesystem. The workflow applies the narrow, checked-in
`ci/landlock-test-tools-minimal.patch` to skip those fixtures and use the
absolute system poweroff path because the guest inherits a deliberately narrow
host `PATH`. `git apply` fails closed if a future test-tools pin changes the
surrounding init code. The test step follows the upstream harness pattern:
stdin is `/dev/null`, output is drained through a bounded `cat`, and `pipefail`
preserves the UML command's status. This keeps CI deterministic without
changing Landlock's test command or forwarding host environment state.

The UML harness currently produces x86_64 kernels, so this compatibility matrix
runs on amd64. The regular build and integration workflows separately compile
and test the native static artifact on both amd64 and arm64. Other architectures
are not release targets.

These pinned kernels are the authoritative compatibility signal. A disposable
[Debian sid test box](debian-sid-testbox.md) covers the complementary case of a
distribution kernel and a current userland, but no result from it gates a
release.

## Updating the pins

1. Select an exact commit from the corresponding `linux-X.Y.y` branch in
   `landlock-lsm/linux` and confirm its ABI from the upstream Landlock test
   matrix.
2. Update the kernel commit in both workflow matrices. If the test harness must
   change, update `LANDLOCK_TEST_TOOLS_COMMIT` separately and review its diff.
3. Let all cold kernel-build jobs finish. Do not weaken
   `fail-on-cache-miss` or restore a kernel under a non-exact fallback key.
4. Confirm that the guest probe reports the expected ABI and that all boundary
   and offline integration tests pass before merging.

Moving branch names and downloaded third-party kernel binaries are deliberately
not used as test inputs. A pin update is a supply-chain change and should remain
visible in review.

## Reviewing new rights and ABIs

Landrun constructs custom handled-access sets instead of selecting every right
known to `go-landlock`. Upgrading the dependency or running on a newer kernel
therefore must not silently widen an existing policy profile. The
`maxPolicyABI` constant records the newest ABI whose semantics landrun exposes,
and `TestHandledAccessSetsMatchPolicyContract` pins the exact filesystem,
network, and scoped sets. The ABI 10 UML job also verifies that UDP remains
absent from the effective policy.

For each new Landlock ABI or dependency release:

1. Inventory every new access right, scope, restrict flag, and enforcement
   semantic in the kernel and `go-landlock` release notes.
2. Leave new access rights out of the handled sets until landrun defines an
   explicit policy contract. Do not infer opt-in from the dependency's maximum
   preset.
3. Before raising `maxPolicyABI`, add the CLI or configuration input, validation,
   `RequiredABI` boundary, effective-policy name, and fail-closed behavior for
   every newly exposed control.
4. Add an exact-set unit assertion, one-below/at-boundary tests, a pinned-kernel
   assertion, and negative tests proving existing profiles do not acquire the
   new right implicitly.
5. Update the README limitations, usage guidance, and changelog with any policy
   semantic or minimum-ABI change.

Kernel enforcement improvements that do not add an access right, such as TSYNC,
and audit-selection flags are tracked separately in the effective-policy report
and still require boundary tests before adoption.
