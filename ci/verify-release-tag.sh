#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <tag> <expected-commit>" >&2
    exit 2
fi

tag="$1"
expected_commit="$2"
signer_fingerprint="F6422E9F521C8EA3E540198425B3790094DC0CB7"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release tag must be an exact vMAJOR.MINOR.PATCH version: $tag" >&2
    exit 1
fi

if [[ "$(git cat-file -t "$tag")" != "tag" ]]; then
    echo "release tag must be annotated: $tag" >&2
    exit 1
fi

tag_commit="$(git rev-list -n 1 "$tag")"
if [[ "$tag_commit" != "$expected_commit" ]]; then
    echo "tag $tag resolves to $tag_commit, expected $expected_commit" >&2
    exit 1
fi

if ! git merge-base --is-ancestor "$tag_commit" origin/main; then
    echo "tagged commit is not reachable from origin/main: $tag_commit" >&2
    exit 1
fi

release_gpg_home="$(mktemp -d)"
trap 'rm -rf -- "$release_gpg_home"' EXIT
chmod 700 "$release_gpg_home"
export GNUPGHOME="$release_gpg_home"

curl --fail --silent --show-error --location https://github.com/Darkflib.gpg |
    gpg --batch --quiet --import

if ! gpg --batch --with-colons --fingerprint |
    grep -Fq "fpr:::::::::${signer_fingerprint}:"; then
    echo "downloaded release key does not contain pinned fingerprint $signer_fingerprint" >&2
    exit 1
fi

set +e
verification_output="$(git verify-tag --raw "$tag" 2>&1)"
verification_status=$?
set -e
printf '%s\n' "$verification_output"
if [[ $verification_status -ne 0 ]] ||
    [[ "$verification_output" != *"[GNUPG:] VALIDSIG"* ]] ||
    [[ "$verification_output" != *"$signer_fingerprint"* ]]; then
    echo "tag $tag is not validly signed by $signer_fingerprint" >&2
    exit 1
fi

echo "Verified signed release tag $tag at $tag_commit"
