# devsec.hardening_audit

Internal shared role used by `os_hardening`, `ssh_hardening`,
`mysql_hardening` and `nginx_hardening`. It captures a baseline before a role
changes the host, captures the same resources afterwards and writes an item
level comparison to:

```text
/var/log/devsec-hardening/hardening-baseline.json
```

Reports from multiple roles are merged by host. Existing role variables remain
the source of expected values; no duplicate compliance settings are required.

## Variables

- `hardening_audit_enabled` (default: `true`): enable capture and reporting.
- `hardening_audit_fail_on_noncompliance` (default: `false`): fail after the
  report is written when at least one expected value is not met.
- `hardening_audit_report_file`: per-host report path.
- `hardening_audit_command_timeout` (default: `30`): timeout for commands such
  as `sshd -T` and `nginx -t`.
- `hardening_audit_show_summary` (default: `true`): print changed and
  noncompliant counts at the end of each role.
- `hardening_audit_fetch_report` (default: `false`): fetch the report to the
  control node.
- `hardening_audit_controller_report_dir`: fetch destination.

The report contains:

- `baseline.before` and `baseline.after` file hashes, modes and ownership.
- `changes`: exact options, before/after values and expected values.
- `file_changes`: unified diffs for every changed file.
- `noncompliant`: checks whose post-hardening value differs from the role
  variable.
- `checks` and `summary`: full check state and counts.

The report intentionally contains no timestamps. A second run with no
configuration change does not rewrite the report.
