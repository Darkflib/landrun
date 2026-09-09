#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^(4|6|9|10)$ ]]; then
    echo "usage: $0 <expected-abi: 4|6|9|10>" >&2
    exit 2
fi

expected_abi="$1"

fail() {
    echo "ABI ${expected_abi} test failed: $*" >&2
    exit 1
}

require_contains() {
    local value="$1"
    local expected="$2"
    [[ "$value" == *"$expected"* ]] || fail "policy record is missing: $expected"
}

require_absent() {
    local value="$1"
    local unexpected="$2"
    [[ "$value" != *"$unexpected"* ]] || fail "policy record unexpectedly contains: $unexpected"
}

probe_output="$(./landrun --probe-json)"
echo "Probed Landlock support: ${probe_output}"
actual_abi="$(sed -n 's/.*"abi":\([0-9][0-9]*\).*/\1/p' <<<"$probe_output")"
[[ "$actual_abi" == "$expected_abi" ]] || fail "probed ABI ${actual_abi:-unknown}, expected ${expected_abi}"
require_contains "$probe_output" '"supported":true'

policy_output="$(./landrun --log-level debug --best-effort --rox ./landrun -- ./landrun --probe-json 2>&1)"
echo "$policy_output"
policy_record="$(sed -n 's/^.*Effective Landlock policy: //p' <<<"$policy_output" | tail -n 1)"
[[ -n "$policy_record" ]] || fail "no effective policy record was emitted"

require_contains "$policy_record" '"applied":true'
require_contains "$policy_record" "\"kernel_abi\":${expected_abi}"
require_contains "$policy_record" '"best_effort":true'
require_contains "$policy_record" '"truncate"'
require_contains "$policy_record" '"handled_network_rights":["bind_tcp","connect_tcp"]'
require_absent "$policy_record" 'bind_udp'
require_absent "$policy_record" 'connect_udp'
require_absent "$policy_record" 'send_udp'

case "$expected_abi" in
    4)
        require_contains "$policy_record" '"policy_abi":4'
        require_contains "$policy_record" '"handled_scopes":[]'
        require_contains "$policy_record" '"thread_synchronized":false'
        require_absent "$policy_record" '"ioctl_dev"'
        require_absent "$policy_record" '"resolve_unix"'
        ;;
    6)
        require_contains "$policy_record" '"policy_abi":6'
        require_contains "$policy_record" '"ioctl_dev"'
        require_contains "$policy_record" '"handled_scopes":["abstract_unix_socket","signal"]'
        require_contains "$policy_record" '"thread_synchronized":false'
        require_absent "$policy_record" '"resolve_unix"'
        ;;
    9|10)
        require_contains "$policy_record" '"policy_abi":9'
        require_contains "$policy_record" '"ioctl_dev"'
        require_contains "$policy_record" '"resolve_unix"'
        require_contains "$policy_record" '"handled_scopes":["abstract_unix_socket","signal"]'
        require_contains "$policy_record" '"thread_synchronized":true'
        ;;
esac

set +e
strict_output="$(./landrun --log-level error --rox ./landrun -- ./landrun --probe-json 2>&1)"
strict_status=$?
set -e
if ((expected_abi < 9)); then
    [[ $strict_status -eq 125 ]] || fail "strict ABI-9 policy returned ${strict_status}, expected 125"
else
    [[ $strict_status -eq 0 ]] || fail "strict ABI-9 policy returned ${strict_status}, expected 0: ${strict_output}"
fi

set +e
audit_output="$(./landrun --log-level debug --best-effort --log-enable-subprocesses --rox ./landrun -- ./landrun --probe-json 2>&1)"
audit_status=$?
set -e
if ((expected_abi < 7)); then
    [[ $audit_status -eq 125 ]] || fail "unsupported explicit audit policy returned ${audit_status}, expected 125"
else
    [[ $audit_status -eq 0 ]] || fail "supported explicit audit policy returned ${audit_status}, expected 0: ${audit_output}"
    require_contains "$audit_output" '"audit_flags":["enable_subprocesses"]'
fi

./test.sh --no-build --keep-binary --offline
