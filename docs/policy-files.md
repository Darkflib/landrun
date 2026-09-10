# Policy files

Landrun can load repeatable sandbox options from a versioned JSON file while
keeping the command to execute explicit on the command line:

```bash
landrun --policy ./landrun-policy.json -- ./application
```

Exactly one `--policy` flag is accepted per invocation.

Policy files are useful for reviewed application profiles. They are not a
separate policy language: each JSON key maps directly to an existing CLI flag.

## Example

```json
{
  "version": 1,
  "ro": [
    "/usr",
    "/etc/ssl/certs",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/hosts"
  ],
  "rw": ["./data"],
  "connect-tcp": [443],
  "env": ["LANG", "APP_MODE=production"],
  "best-effort": true,
  "add-exec": true,
  "ldd": true
}
```

Run it with:

```bash
landrun --policy ./landrun-policy.json -- ./application
```

The policy file never selects the command. Review the file as security-sensitive
input: its path, network, environment, and descriptor entries grant capabilities
to the target process.

## Version 1 keys

The required `version` field must be `1`. The remaining keys are optional and
use the same values and security semantics as their namesake flags:

- list-of-string rules: `ro`, `rox`, `rw`, `rwx`, and `unix`;
- list-of-integer rules: `bind-tcp` and `connect-tcp`;
- target capabilities: `env` (strings) and `preserve-fd` (integers);
- compatibility and path handling: `best-effort` and `ignore-missing`;
- domain controls: `unrestricted-filesystem`, `unrestricted-network`, and
  `unrestricted-scoped`;
- audit controls: `log-disable-originating`, `log-enable-subprocesses`, and
  `log-disable-subdomains`; and
- executable helpers: `add-exec` and `ldd`.

The file does not accept `policy`, `log-level`, `probe`, `probe-json`, a command,
or command arguments. Logging and introspection remain launcher controls.

## Composition with CLI flags

When both sources are present, list values from the file are followed by list
values from the command line. Existing validation then sorts and deduplicates
paths and ports. A boolean enabled by either source remains enabled; there is no
CLI syntax for negating a boolean enabled by a policy file.

This composition can intentionally add grants:

```bash
landrun \
  --policy ./base-policy.json \
  --rw "$PWD/debug-output" \
  --env DEBUG=1 \
  -- \
  ./application
```

Consequently, verifying a policy file alone is not enough when callers may add
flags. Review the complete invocation and inspect debug-level requested/effective
policy output when validating a deployment. Contradictory combinations, such as
`unrestricted-network` together with `connect-tcp`, remain launcher errors.

## Parsing and path semantics

Policy parsing is deliberately strict:

- the input must be a regular file no larger than 1 MiB;
- it must contain exactly one JSON object;
- unknown fields, duplicate object keys, `null` values, wrong types, malformed
  JSON, and unsupported versions are rejected with launcher status 125; and
- no shell, environment-variable, tilde, or template expansion is performed.

Relative policy paths keep the CLI's existing meaning: they are interpreted
relative to landrun's current working directory, not the policy file's directory.
Environment entries use the existing `KEY` or `KEY=VALUE` form, and preserved
descriptor numbers must already be open when landrun starts.

Like command-line policy construction, the file is read before Landlock is
applied. Keep it under the same change control as the invocation that selects it.
