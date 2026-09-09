# Security policy

Landrun is a defense-in-depth sandbox launcher. A defect that weakens or
silently omits a requested restriction can be security-sensitive even when the
underlying Landlock implementation is behaving as designed.

## Supported versions

While landrun is pre-1.0, security fixes are made on `main` and included in the
next release. Only the latest tagged release is supported; older tags do not
receive security backports. Report suspected vulnerabilities against either
the latest tag or the current `main` branch.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting form](https://github.com/Darkflib/landrun/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include as much of the following as is practical:

- the affected landrun version or commit;
- the Linux kernel version and Landlock ABI reported by `landrun --probe`;
- the command and policy needed to reproduce the behavior;
- the restriction you expected and what happened instead;
- the security impact and any known workaround; and
- whether the report may be shared with an affected dependency or the Linux
  Landlock maintainers.

Reports are handled in the private advisory until a fix and coordinated
disclosure are ready. Please avoid sharing exploit details publicly before
that point.

## Scope

Examples of in-scope reports include policy bypasses, silently dropped rules,
launcher capability leaks, unsafe command or dependency resolution, and cases
where documented fail-closed behavior instead fails open.

Landlock deliberately does not provide complete process, identity, resource,
or network isolation. Behavior that is already documented as outside
Landlock's security boundary is not by itself a landrun vulnerability. See the
[security review](docs/security-review.md) and
[usage guide](docs/usage-guide.md) for the current boundary and composition
guidance.
