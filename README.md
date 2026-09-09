# Landrun <img src="https://avatars.githubusercontent.com/u/21111839?s=48&v=4" align="right"/>

A lightweight, secure sandbox for running Linux processes using Landlock. Think firejail, but with kernel-level security and minimal overhead.

Linux Landlock is a kernel-native security module that lets unprivileged processes sandbox themselves.

Landrun is designed to make it practical to sandbox any command with fine-grained filesystem and network access controls. No root. No containers. No SELinux/AppArmor configs.

It's lightweight, auditable, and wraps Landlock up to v9 features (file access, TCP restrictions, IPC scoping, and UNIX-socket controls).

[Binaries are not trustworthy](https://zoup.org/landrun-binaries-are-not-trustworthy/)

> [!WARNING]
> Landrun is a defense-in-depth tool, not a complete container or network
> firewall. Review the [known security issues and limitations](docs/security-review.md)
> before using it with hostile code. Remediation work is tracked in the
> [hardening roadmap](ROADMAP.md).

## Features

- 🔒 Kernel-level security using Landlock (up to ABI v9; ABI v10 UDP controls are not enabled)
- 🚀 Lightweight and fast execution
- 🛡️ Fine-grained access control for directories and files
- 🔄 Support for read and write paths
- ⚡ Path-specific execution permissions
- 🌐 TCP network access control (binding and connecting)
- 📡 IPC scoping for abstract UNIX sockets and signals (ABI v6+)
- 🔌 Pathname UNIX domain socket connect/sendmsg control (ABI v9+)
- 📝 Audit logging configuration for Landlock denials (ABI v7+)

## Demo

<p align="center">
  <img src="demo.gif" alt="landrun demo" width="700"/>
</p>

## Requirements

- Linux kernel 5.13 or later with Landlock enabled
- Linux kernel 6.7 or later for network restrictions (TCP bind/connect)
- Go 1.24 or later (for building from source)

> By default landrun targets the highest Landlock ABI (v9). On older kernels, pass `--best-effort` so it gracefully degrades to the best ABI the running kernel supports (see [Best-Effort Mode](#best-effort-mode)).

## Installation

### Quick Install

```bash
go install github.com/zouuup/landrun/cmd/landrun@latest
```

### From Source

```bash
git clone https://github.com/zouuup/landrun.git
cd landrun
go build -o landrun cmd/landrun/main.go
sudo cp landrun /usr/local/bin/
```

### Distros

#### Arch (AUR)

- [stable](https://aur.archlinux.org/packages/landrun) maintained by [Vcalv](https://github.com/vcalv)
- [latest commit](https://aur.archlinux.org/packages/landrun-git) maintained by [juxuanu](https://github.com/juxuanu/)

#### Slackware

maintained by [r1w1s1](https://github.com/r1w1s1)

[Slackbuild](https://slackbuilds.org/repository/15.0/network/landrun/?search=landrun)
```bash
sudo sbopkg -i packagename
```

#### Debian/Ubuntu

Available in Ubuntu since `questing` / `resolute` (26.04 LTS), available in Debian since `forky`.

```bash
sudo apt install landrun
```


## Usage

Basic syntax:

```bash
landrun [options] <command> [args...]
```

### Options

- `--ro <path>`: Allow read-only access to specified path (can be specified multiple times or as comma-separated values)
- `--rox <path>`: Allow read-only access with execution to specified path (can be specified multiple times or as comma-separated values)
- `--rw <path>`: Allow read-write access to specified path (can be specified multiple times or as comma-separated values)
- `--rwx <path>`: Allow read-write access with execution to specified path (can be specified multiple times or as comma-separated values)
- `--unix <path>`: Allow `connect(2)`/`sendmsg(2)` on the specified pathname UNIX domain socket (Landlock ABI v9+; can be specified multiple times or as comma-separated values)
- `--bind-tcp <port>`: Allow binding to a TCP port in the range 0-65535 (port 0 allows the kernel to select an ephemeral port; can be specified multiple times or as comma-separated values)
- `--connect-tcp <port>`: Allow connecting to a TCP port in the range 1-65535 (port 0 is rejected; can be specified multiple times or as comma-separated values)
- `--env <var>`: Environment variable to pass to the sandboxed command (format: KEY=VALUE or just KEY to pass current value)
- `--preserve-fd <fd>`: Preserve an already-open file descriptor numbered 3 or greater across `exec` (can be specified multiple times or as comma-separated values)
- `--best-effort`: Use best effort mode, falling back to less restrictive sandbox if necessary [default: disabled]
- `--log-level <level>`: Set logging level (error, info, debug) [default: "error"]
- `--unrestricted-network`: Allows unrestricted network access (disables all network restrictions)
- `--unrestricted-filesystem`: Allows unrestricted filesystem access (disables all filesystem restrictions)
- `--unrestricted-scoped`: Allows unrestricted IPC scoping, i.e. does not restrict abstract UNIX sockets and signals (Landlock ABI v6+) [default: disabled]
- `--ignore-missing`: Gracefully ignore paths that do not exist instead of failing [default: disabled]
- `--log-disable-originating`: Disable audit logging of denials from the originating process (Landlock ABI v7+)
- `--log-enable-subprocesses`: Enable audit logging of denials after `execve(2)` in subprocesses (Landlock ABI v7+)
- `--log-disable-subdomains`: Disable audit logging of denials from nested Landlock domains (Landlock ABI v7+)
- `--add-exec`: Automatically adds the executing binary to --rox
- `--ldd`: Automatically adds required libraries to --rox
- `--probe`: Report the running kernel's highest supported Landlock ABI and exit
- `--probe-json`: Report the Landlock ABI as machine-readable JSON and exit

### Important Notes

- You must explicitly add the directory or files to the command you want to run with `--rox` flag
- For system commands, you typically need to include `/usr/bin`, `/usr/lib`, and other system directories
- Use `--rwx` for directories or files where you need both write access and the ability to execute files
- Network restrictions require Linux kernel 6.7 or later with Landlock ABI v4
- By default, no environment variables are passed to the sandboxed command. Use `--env` to explicitly pass environment variables
- Standard input, output, and error are inherited. All other open file descriptors are closed on `exec` unless explicitly listed with `--preserve-fd`
- Invalid policy and launcher/setup failures exit with status 125. Once the command is executed, its own exit status is preserved
- A rule flag cannot be combined with its matching unrestricted-domain flag; for example, use either `--connect-tcp` rules or `--unrestricted-network`, not both
- Explicit controls that require a newer Landlock ABI fail with status 125 even under `--best-effort`; the probe commands show the ABI available on the current kernel
- The `--best-effort` flag allows graceful degradation on older kernels that don't support all requested restrictions. Because the default target is Landlock ABI v9, you will usually want `--best-effort` unless you are on a very recent kernel
- Paths can be specified either using multiple flags or as comma-separated values (e.g., `--ro /usr,/lib,/home`)
- If no paths or network rules are specified and neither `--unrestricted-filesystem` nor `--unrestricted-network` is set, landrun applies the maximum filesystem and network restrictions supported by the selected Landlock ABI; IPC scoping is governed separately by `--unrestricted-scoped` (see the next point), and operations outside Landlock's scope remain unaffected
- By default, IPC scoping is restricted: the sandboxed process cannot connect to abstract UNIX sockets or send signals to processes outside its Landlock domain (ABI v6+). Use `--unrestricted-scoped` if this breaks your workload (e.g. some X11 or D-Bus setups)
- On ABI v9+ kernels, connecting to pathname UNIX domain sockets created outside the sandbox (e.g. DNS/NSS via `nscd`, D-Bus, database sockets) is restricted. Grant access to specific sockets with `--unix <path>`

### Environment Variables

- `LANDRUN_LOG_LEVEL`: Set logging level (error, info, debug)

Debug logging prints the normalized requested policy followed by a structured
`Effective Landlock policy` record after successful enforcement, or after an
intentional all-unrestricted no-op evaluation (`applied:false`). The record
distinguishes the running kernel ABI from the policy ABI and lists the access
rights and scopes actually handled after best-effort downgrading. `policy_abi`
is the lowest ABI that describes those handled rights, scopes, and audit flags;
kernel-only enforcement improvements such as ABI 8 TSYNC are reported
separately.

### Quick examples

Check the host's Landlock ABI:

```bash
landrun --probe
```

Run a command with one read-only input and one writable data directory:

```bash
landrun \
    --best-effort \
    --add-exec \
    --ldd \
    --ro "$PWD/config.toml" \
    --rw "$PWD/data" \
    -- \
    /opt/myapp/bin/myapp --config "$PWD/config.toml"
```

Allow outbound TCP connections to port 443:

```bash
landrun \
    --best-effort \
    --add-exec \
    --rox /usr/lib \
    --ro /etc/ssl/certs,/etc/resolv.conf,/etc/nsswitch.conf,/etc/hosts \
    --connect-tcp 443 \
    -- \
    /usr/bin/curl https://example.com/
```

The TCP rule is port-based, not a hostname or destination-address allowlist,
and this version does not restrict UDP. Library, certificate, and name-service
paths vary by distribution. See the [usage guide](docs/usage-guide.md) for
practical CLI, build, server, UNIX-socket, descriptor-passing, systemd, and
container examples, plus guidance on composing Landrun with other controls.

## Security

landrun uses Linux's Landlock to create a secure sandbox environment. It provides:

- File system access control
- Directory access restrictions
- Execution control
- TCP network restrictions
- Limited IPC scoping for signals and abstract UNIX sockets when supported by the kernel ABI
- Default restrictive mode when no rules are specified

Landlock is an access-control system that enables processes to securely restrict themselves and their future children. As a stackable Linux Security Module (LSM), it creates additional security layers on top of existing system-wide access controls, helping to mitigate security impacts from bugs or malicious behavior in applications.

Landrun does not replace Unix identities and permissions, SELinux/AppArmor,
capability reduction, seccomp, namespaces, cgroups, or firewall/network policy.
Those controls cover different boundaries and combine by further restricting
the workload. See [How Landlock composes with other controls](docs/usage-guide.md#how-landlock-composes-with-other-controls).

### Landlock Access Control Rights

landrun leverages Landlock's fine-grained access control mechanisms, which include:

**File-specific rights:**

- Execute files (`LANDLOCK_ACCESS_FS_EXECUTE`)
- Write to files (`LANDLOCK_ACCESS_FS_WRITE_FILE`)
- Read files (`LANDLOCK_ACCESS_FS_READ_FILE`)
- Truncate files (`LANDLOCK_ACCESS_FS_TRUNCATE`) - Available since Landlock ABI v3
- IOCTL operations on devices (`LANDLOCK_ACCESS_FS_IOCTL_DEV`) - Available since Landlock ABI v5
- Connect/sendmsg on pathname UNIX sockets (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`) - Available since Landlock ABI v9 (granted per-path with `--unix`)

**Directory-specific rights:**

- Read directory contents (`LANDLOCK_ACCESS_FS_READ_DIR`)
- Remove directories (`LANDLOCK_ACCESS_FS_REMOVE_DIR`)
- Remove files (`LANDLOCK_ACCESS_FS_REMOVE_FILE`)
- Create various filesystem objects (char devices, directories, regular files, sockets, etc.)
- Refer/reparent files across directories (`LANDLOCK_ACCESS_FS_REFER`) - Available since Landlock ABI v2

**Network-specific rights** (requires Linux 6.7+ with Landlock ABI v4):

- Bind to specific TCP ports (`LANDLOCK_ACCESS_NET_BIND_TCP`)
- Connect to specific TCP ports (`LANDLOCK_ACCESS_NET_CONNECT_TCP`)

**IPC scoping** (requires Linux 6.12+ with Landlock ABI v6):

- Restrict connections to abstract UNIX sockets outside the domain (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`)
- Restrict sending signals to processes outside the domain (`LANDLOCK_SCOPE_SIGNAL`)

These are restricted by default and can be relaxed with `--unrestricted-scoped`.

### Limitations

- Landlock must be supported by your kernel
- Network restrictions require Linux kernel 6.7 or later with Landlock ABI v4
- TCP restrictions only apply to "classic" TCP sockets, not Multipath TCP. Since Go 1.24, `net.Listen` defaults to Multipath TCP and therefore cannot currently be restricted by Landlock (kernel bug [landlock-lsm/linux#54](https://github.com/landlock-lsm/linux/issues/54))
- This version does not restrict UDP traffic
- `--best-effort` may still omit unrequested higher-ABI coverage, but it will not drop an explicitly requested path, TCP, UNIX-socket, or audit-logging control
- `--ldd` resolves dependencies without executing `ldconfig` or another helper; it supports standard Intel and ARM multilib layouts and fails closed for other ELF machine types, ambiguous 32-bit ARM float-ABI flags, or libraries only discoverable through a non-standard loader-cache entry
- The resolved command is opened before policy setup and executed by descriptor, preventing a path replacement between policy construction and launch; scripts still require execute access to their shebang interpreter
- Some operations may require additional permissions
- Files, directories, and sockets intentionally preserved with `--preserve-fd` are not retroactively restricted by Landlock

## Kernel Compatibility Table

| Feature                                       | Minimum Kernel Version | Landlock ABI Version |
| --------------------------------------------- | ---------------------- | -------------------- |
| Basic filesystem sandboxing                   | 5.13                   | 1                    |
| File referring/reparenting control            | 5.19                   | 2                    |
| File truncation control                       | 6.2                    | 3                    |
| Network TCP restrictions                      | 6.7                    | 4                    |
| IOCTL on special files                        | 6.10                   | 5                    |
| IPC scoping (abstract UNIX sockets, signals)  | 6.12                   | 6                    |
| Audit logging of denials                      | 6.15                   | 7                    |
| Thread synchronization (TSYNC)                | 7.0                    | 8                    |
| Pathname UNIX socket connect/sendmsg control  | latest                 | 9                    |

## Troubleshooting

If you receive "permission denied" or similar errors:

1. Ensure you've added all necessary paths with `--ro` or `--rw`
2. Try running with `--log-level debug` to see detailed permission information
3. Check that Landlock is supported and enabled on your system:
   ```bash
   grep -E 'landlock|lsm=' /boot/config-$(uname -r)
   # alternatively, if there are no /boot/config-* files
   zgrep -iE 'landlock|lsm=' /proc/config.gz
   # another alternate method
   grep -iE 'landlock|lsm=' /lib/modules/$(uname -r)/config
   ```
   You should see `CONFIG_SECURITY_LANDLOCK=y` and `lsm=landlock,...` in the output
4. For network restrictions, verify your kernel version is 6.7+ with Landlock ABI v4:
   ```bash
   uname -r
   ```

## Technical Details

### Implementation

This project uses the [landlock-lsm/go-landlock](https://github.com/landlock-lsm/go-landlock) package (v0.10.0) for sandboxing, which provides filesystem, network and IPC-scope restrictions. The current implementation intentionally targets Landlock ABI v9 and supports:

- Read/write/execute restrictions for files and directories
- TCP port binding restrictions
- TCP port connection restrictions
- IPC scoping (abstract UNIX sockets and signals)
- Pathname UNIX domain socket connect/sendmsg control (`--unix`)
- Audit logging configuration for Landlock denials (`--log-*`)
- Graceful handling of missing paths (`--ignore-missing`)
- Best-effort mode for graceful degradation on older kernels

The dependency also supports Landlock ABI v10 UDP bind/connect-send controls,
but landrun does not expose those controls yet; UDP remains unrestricted by
landrun's network policy.

### Best-Effort Mode

By default, landrun targets the highest Landlock ABI (v9) in strict mode, so on any kernel that does not support v9 it will fail unless `--best-effort` is used.

When using `--best-effort` (disabled by default), landrun will gracefully degrade to using the best available Landlock version on the current kernel. This means:

- On Linux 7.0+: All of the below, plus thread synchronization (TSYNC) and, on ABI v9 kernels, pathname UNIX socket controls
- On Linux 6.15+: Adds audit logging configuration (ABI v7)
- On Linux 6.12+: Adds IPC scoping for abstract UNIX sockets and signals (ABI v6)
- On Linux 6.10+: Filesystem, network and IOCTL restrictions (ABI v5)
- On Linux 6.7+: Full filesystem and network restrictions (ABI v4)
- On Linux 6.2-6.6: Filesystem restrictions including truncation, but no network restrictions
- On Linux 5.19-6.1: Basic filesystem restrictions including file reparenting, but no truncation control or network restrictions
- On Linux 5.13-5.18: Basic filesystem restrictions without file reparenting, truncation control, or network restrictions
- On older Linux: No restrictions (sandbox disabled)

When no rules are specified and neither `--unrestricted-filesystem` nor `--unrestricted-network` is set, landrun will apply the maximum filesystem and network restrictions available for the current kernel version. On ABI v6+ kernels IPC scoping is restricted by default as well, unless `--unrestricted-scoped` is set.

### Tests

The project includes a comprehensive test suite that verifies:

- Basic filesystem access controls (read-only, read-write, execute)
- Directory traversal and path handling
- Network restrictions (TCP bind/connect)
- Environment variable isolation
- System command execution
- Edge cases and regression tests

Run the tests with:

```bash
./test.sh
```

Use `--keep-binary` to preserve the test binary after completion:

```bash
./test.sh --keep-binary
```

Use `--use-system` to test against the system-installed landrun binary:

```bash
./test.sh --use-system
```

The default test suite uses only local deterministic peers. Public-network
smoke tests for `example.com` and `kernel.org` are opt-in with `--online` and
should not be used as a CI or release gate:

```bash
./test.sh --online
```

## Future Features

Based on the Linux Landlock API capabilities, we plan to add:

- 🔒 Enhanced filesystem controls with more fine-grained permissions
- 🌐 Support for UDP and other network protocol restrictions (when supported by Linux kernel)
- 🛡️ Additional security features as they become available in the Landlock API

## Acknowledgements

This project wouldn't exist without:

- [Landlock](https://landlock.io), the kernel security module enabling unprivileged sandboxing - maintained by [@l0kod](https://github.com/l0kod)
- [go-landlock](https://github.com/landlock-lsm/go-landlock), the Go bindings powering this tool - developed by [@gnoack](https://github.com/gnoack)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
