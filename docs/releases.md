# Release process and verification

Landrun releases are created by `.github/workflows/release.yml` from signed,
annotated semantic-version tags. The workflow only publishes Linux amd64 and
arm64 artifacts.

## Maintainer release process

1. Update `cmd/landrun/main.go` so `Version` matches the planned tag without the
   leading `v`.
2. Move the relevant entries from `Unreleased` into a dated release section in
   `CHANGELOG.md` and merge the release preparation to `main`.
3. Wait for successful push runs of the Build, Go version compatibility,
   Security, and Landlock ABI matrix workflows on that exact `main` commit.
4. Create an annotated GPG-signed tag and push it without moving or recreating
   an existing release tag:

   ```bash
   git switch main
   git pull --ff-only
   git tag --sign v0.1.18 --message "landrun v0.1.18"
   git push origin v0.1.18
   ```

The release gate accepts exact `vMAJOR.MINOR.PATCH` names and pins the release
signer's primary GPG fingerprint to
`F6422E9F521C8EA3E540198425B3790094DC0CB7`. It rejects lightweight, unsigned,
invalidly signed, off-main, version-mismatched, or unchecked tags. Changing the
trusted signing key requires a reviewed source change.

After the gate, native amd64 and arm64 jobs rebuild and run the offline
integration suite. The publication job then produces a SHA-256 manifest, an
SPDX JSON SBOM, GitHub/Sigstore build-provenance and SBOM attestations, and a
GitHub release. It refuses to replace an existing release.

## Release contents

Each release contains:

- `landrun-linux-amd64` and `landrun-linux-arm64`;
- one `.buildinfo` file per binary with embedded Go module, VCS, target, and
  toolchain data;
- `SHA256SUMS` covering both binaries, both build-info files, and the SBOM;
- `landrun.spdx.json`, an SPDX JSON software bill of materials; and
- downloadable Sigstore bundles for build provenance and the SBOM attestation.

GitHub also stores the attestations against the repository so they can be
verified without trusting the downloadable bundle files.

## Verify a release

Download the files for one release into an empty directory. Verify the checksum
manifest before executing the binary:

```bash
sha256sum --check SHA256SUMS
```

Inspect the embedded identity without running the binary if Go is installed:

```bash
go version -m ./landrun-linux-amd64
```

Or ask the binary to report its version, full source revision, and Go toolchain:

```bash
./landrun-linux-amd64 --version
```

Verify GitHub's signed build provenance for the binary and checksum manifest:

```bash
gh attestation verify ./landrun-linux-amd64 --repo Darkflib/landrun
gh attestation verify ./SHA256SUMS --repo Darkflib/landrun
```

The SBOM attestation associates `landrun.spdx.json` with both release binaries.
Use `gh attestation verify --format json` when a machine-readable verification
result is needed.

The signed source tag remains independently inspectable with `git verify-tag`:

```bash
git fetch origin tag v0.1.18
git verify-tag v0.1.18
```

Verification establishes who authorized the source tag, which workflow built
the artifact, and whether the downloaded bytes match the published subject. It
does not replace review of landrun's documented policy boundary.
