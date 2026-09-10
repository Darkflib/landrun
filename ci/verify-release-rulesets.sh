#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "usage: $0" >&2
    exit 2
fi

repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"

release_actor_id=101405
release_pattern="refs/tags/v*"

rulesets="$(gh api --method GET "repos/${repository}/rulesets")"

get_ruleset() {
    local name="$1"
    local -a ids

    mapfile -t ids < <(jq -r --arg name "$name" '
        .[]
        | select(.name == $name and .target == "tag" and .enforcement == "active")
        | .id
    ' <<<"$rulesets")

    if [[ ${#ids[@]} -ne 1 ]]; then
        echo "expected exactly one active tag ruleset named '$name'; found ${#ids[@]}" >&2
        return 1
    fi

    gh api --method GET "repos/${repository}/rulesets/${ids[0]}"
}

creation="$(get_ruleset "Release tag creation")"
if ! jq -e \
    --arg pattern "$release_pattern" \
    --argjson actor_id "$release_actor_id" '
        .conditions.ref_name == {include: [$pattern], exclude: []}
        and ([.rules[].type] | sort) == ["creation"]
        and ((.bypass_actors == null) or .bypass_actors == [{
                actor_id: $actor_id,
                actor_type: "User",
                bypass_mode: "always"
            }])
    ' <<<"$creation" >/dev/null; then
    echo "Release tag creation ruleset does not match the reviewed policy" >&2
    exit 1
fi

immutability="$(get_ruleset "Release tag immutability")"
if ! jq -e \
    --arg pattern "$release_pattern" '
        .conditions.ref_name == {include: [$pattern], exclude: []}
        and ([.rules[].type] | sort) == ["deletion", "update"]
        and ([.rules[] | select(.type == "update")][0].parameters
            == {update_allows_fetch_and_merge: false})
        and ((.bypass_actors == null) or .bypass_actors == [])
    ' <<<"$immutability" >/dev/null; then
    echo "Release tag immutability ruleset does not match the reviewed policy" >&2
    exit 1
fi

if jq -e '.bypass_actors == null' <<<"$creation" >/dev/null ||
    jq -e '.bypass_actors == null' <<<"$immutability" >/dev/null; then
    echo "GitHub omitted bypass actors for this token; visible ruleset policy verified"
fi

echo "Verified active release-tag creation and immutability rulesets"
