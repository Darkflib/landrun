# Landlock audit logging

Landlock ABI 7 added controls for selecting which denied accesses are sent to
the Linux audit subsystem. These controls do not change enforcement: an access
is still denied whether or not an audit record is selected.

Audit records and Landlock tracepoints are system-wide and may expose paths,
ports, process identities, and policy details. Access to them is therefore
controlled by the host administrator. Landrun does not attempt to provide an
unprivileged per-sandbox audit stream.

## Check support without privileges

Query the kernel ABI as the user who will run the sandbox:

```bash
landrun --probe-json
```

An ABI of 7 or later supports Landlock audit-selection flags. This probe does
not prove that the kernel audit subsystem is built, active, or readable by the
current user.

Landrun can also report the audit flags applied to a policy without access to
the system audit log:

```bash
landrun \
    --best-effort \
    --log-level debug \
    --log-enable-subprocesses \
    --add-exec \
    --ldd \
    --ro /etc/hostname \
    -- \
    /usr/bin/cat /etc/passwd
```

Before executing the command, debug output includes an `Effective Landlock
policy` JSON record. On a supported kernel, this example contains:

```json
"audit_flags":["enable_subprocesses"]
```

This confirms that the flag was accepted as part of the enforced policy. An
empty `audit_flags` array means the kernel defaults are in use; it does not mean
that auditing is disabled. An explicit audit flag fails with launcher status
125 when the kernel ABI is below 7, including under `--best-effort`.

## Choose the logging scope

By default, the kernel selects denials caused by the executable that created
the Landlock domain, but not denials after a later `execve(2)`. Landrun applies
the domain and then executes the requested command, so use
`--log-enable-subprocesses` when host audit records for that command are wanted.

| Landrun option | Effect |
| --- | --- |
| no audit option | Use the kernel's default selection |
| `--log-enable-subprocesses` | Also select denials after the target or a descendant executes a new program |
| `--log-disable-originating` | Stop selecting denials from landrun and descendants while they retain the same executable image |
| `--log-disable-subdomains` | Stop selecting denials attributed to nested Landlock domains created later |

Enabling subprocess logging for software that routinely probes inaccessible
paths can create substantial noise. Disabling originating or nested-domain
logging can hide useful evidence. Treat these as deployment policy choices,
not generic performance switches.

## Read records as a host administrator

When Linux Audit is available, records use `LANDLOCK_ACCESS` and
`LANDLOCK_DOMAIN` types. Depending on the distribution and local permissions,
an administrator can inspect them with commands such as:

```bash
sudo ausearch -m LANDLOCK_ACCESS,LANDLOCK_DOMAIN
sudo journalctl -k | grep LANDLOCK_
```

The audit subsystem may rate-limit records, and some kernel permission probes
are intentionally marked `NOAUDIT`. Absence of a record is therefore not proof
that an access was allowed. Use the command's observed error and landrun's
effective-policy report when testing enforcement.

For deeper system-wide debugging, newer kernels also expose Landlock
tracepoints. Reading or attaching to them requires elevated host capabilities
and exposes sensitive information, so trace collection belongs in an
administrator-operated observability layer rather than in landrun itself.

## References

- [Linux Landlock userspace API: logging flags](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#logging-abi-7)
- [Linux Landlock system-wide audit and tracing guidance](https://www.kernel.org/doc/html/latest/admin-guide/LSM/landlock.html)
