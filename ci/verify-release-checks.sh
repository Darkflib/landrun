#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <commit>" >&2
    exit 2
fi

commit="$1"
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"

required_workflows=(
    build.yml
    go-compatibility.yml
    security.yml
    abi-matrix.yml
)

for workflow in "${required_workflows[@]}"; do
    response="$(gh api --method GET \
        "repos/${repository}/actions/workflows/${workflow}/runs" \
        -f branch=main \
        -f event=push \
        -f status=completed \
        -f per_page=100)"
    result="$(jq -r --arg commit "$commit" '
        [.workflow_runs[] | select(.head_sha == $commit)]
        | sort_by(.run_number)
        | last
        | if . == null then ["", ""] else [.conclusion, .html_url] end
        | @tsv
    ' <<<"$response")"
    IFS=$'\t' read -r conclusion run_url <<<"$result"
    if [[ "$conclusion" != "success" ]]; then
        echo "required workflow $workflow has no successful completed push run for $commit" >&2
        [[ -n "$run_url" ]] && echo "latest matching run: $run_url ($conclusion)" >&2
        exit 1
    fi
    echo "Verified $workflow: $run_url"
done
