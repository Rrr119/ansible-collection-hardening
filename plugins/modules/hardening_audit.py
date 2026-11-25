#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: hardening_audit
short_description: Capture hardening baselines and report configuration drift
description:
  - Captures selected files, scalar configuration options, sysctl values and
    command results before a hardening role runs.
  - Captures the same state after hardening, returns an item level comparison
    and writes a stable, host based JSON report that can contain multiple roles.
  - The report deliberately contains no timestamps. Running the same role twice
    with the same effective configuration therefore does not modify the report.
options:
  action:
    description: Capture a baseline or compare a baseline with the current state.
    type: str
    required: true
    choices: [capture, compare]
  role:
    description: Hardening role name written to the report.
    type: str
    required: true
  files:
    description:
      - Files to capture.
      - A list item can be a path or a mapping with C(path), C(parser) and
        C(enabled). Supported parsers are C(auto), C(keyvalue), C(ini) and
        C(hash).
    type: list
    elements: raw
    default: []
  checks:
    description:
      - Configuration checks.
      - A check can target a parsed file option, a sysctl value, a command
        output option or a command exit status.
    type: list
    elements: dict
    default: []
  sysctl:
    description:
      - Mapping of sysctl keys to expected values. Each entry is captured from
        C(/proc/sys) and added as a check.
    type: dict
    default: {}
  file_expectations:
    description:
      - Convenience list for checking a mapping of options in one file section.
      - Each item may contain C(path), C(section) and C(options).
    type: list
    elements: dict
    default: []
  before:
    description: Baseline returned by a previous C(capture) call.
    type: dict
  report_file:
    description:
      - Host report path. Existing role sections are merged and preserved.
      - Set to an empty string to disable writing the report.
    type: str
    default: /var/log/devsec-hardening/hardening-baseline.json
  fail_on_noncompliance:
    description: Fail after writing the report when a check is noncompliant.
    type: bool
    default: false
  host:
    description: Host name written to the report.
    type: str
    default: ""
  distribution:
    description: Distribution written to the report.
    type: str
    default: ""
  distribution_version:
    description: Distribution version written to the report.
    type: str
    default: ""
  os_family:
    description: OS family written to the report.
    type: str
    default: ""
  command_timeout:
    description: Timeout in seconds for command based checks.
    type: int
    default: 30
  max_file_size:
    description: Maximum file size captured for line level comparison.
    type: int
    default: 2097152
author:
  - dev-sec (@dev-sec)
"""

EXAMPLES = r"""
- name: Capture the pre-hardening baseline
  devsec.hardening.hardening_audit:
    action: capture
    role: os_hardening
    files:
      - /etc/login.defs
    checks:
      - id: login_defs.PASS_MAX_DAYS
        path: /etc/login.defs
        key: PASS_MAX_DAYS
        expected: "{{ os_auth_pw_max_age }}"
  register: hardening_before

- name: Compare and write the report
  devsec.hardening.hardening_audit:
    action: compare
    role: os_hardening
    before: "{{ hardening_before.snapshot }}"
    files:
      - /etc/login.defs
    checks:
      - id: login_defs.PASS_MAX_DAYS
        path: /etc/login.defs
        key: PASS_MAX_DAYS
        expected: "{{ os_auth_pw_max_age }}"
"""

RETURN = r"""
snapshot:
  description: Captured state returned by C(action=capture).
  returned: when action is capture
  type: dict
changes:
  description: Item level configuration changes.
  returned: when action is compare
  type: list
noncompliant:
  description: Checks that do not match their expected value after hardening.
  returned: when action is compare
  type: list
report:
  description: Complete merged host report.
  returned: when action is compare
  type: dict
summary:
  description: Counts for the current role.
  returned: when action is compare
  type: dict
"""

import difflib
import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import stat
import tempfile

from ansible.module_utils.basic import AnsibleModule


SCHEMA_VERSION = 1
COLLECTION_NAME = "devsec.hardening"


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _clean_value(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_clean_value(item) for item in value]
    text = str(value).strip().rstrip(";").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]
    return re.sub(r"\s+", " ", text)


def _normalize_text(value):
    cleaned = _clean_value(value)
    if isinstance(cleaned, list):
        return [re.sub(r"\s+", " ", str(item).strip()) for item in cleaned]
    if cleaned is None:
        return None
    return re.sub(r"\s+", " ", str(cleaned).strip())


def _values_equal(left, right, case_sensitive=True):
    left = _normalize_text(left)
    right = _normalize_text(right)
    if isinstance(left, list) or isinstance(right, list):
        left_list = left if isinstance(left, list) else [left]
        right_list = right if isinstance(right, list) else [right]
        if not case_sensitive:
            left_list = [str(item).casefold() for item in left_list]
            right_list = [str(item).casefold() for item in right_list]
        return left_list == right_list
    if left is None or right is None:
        return left is right
    if not case_sensitive:
        return str(left).casefold() == str(right).casefold()
    return str(left) == str(right)


def _parse_options(text, parser="auto"):
    options = {}
    section = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue
        section_match = re.match(r"^\[([^\]]+)\]$", line)
        if section_match:
            section = section_match.group(1).strip()
            continue
        if line in ("{", "}"):
            continue

        key = None
        value = None
        ini_match = re.match(r"^([^\s=]+)\s*=\s*(.*)$", line)
        colon_match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s+(.*)$", line)
        if parser == "ini" and "=" in line:
            key, value = line.split("=", 1)
        elif parser == "auto" and ini_match:
            key, value = ini_match.group(1), ini_match.group(2)
        elif parser == "auto" and "=" not in line and colon_match:
            key, value = colon_match.group(1), colon_match.group(2)
        if key is None:
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else None

        key = key.strip().strip("'\"")
        if not key:
            continue
        value = _clean_value(value)
        if value == "{":
            continue
        entry = {
            "value": value,
            "line": line_number,
            "section": section,
        }
        options.setdefault(key, []).append(entry)
    return options


def _owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return str(uid)


def _group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return str(gid)


def _read_file(path, parser, max_file_size):
    path = os.path.expanduser(path)
    result = {
        "path": path,
        "exists": False,
        "sha256": None,
        "size": None,
        "mode": None,
        "owner": None,
        "group": None,
        "is_symlink": False,
        "is_binary": False,
        "lines": [],
        "options": {},
        "error": None,
    }
    try:
        link_stat = os.lstat(path)
        result["is_symlink"] = stat.S_ISLNK(link_stat.st_mode)
        file_stat = os.stat(path)
        result.update(
            {
                "exists": True,
                "size": file_stat.st_size,
                "mode": oct(stat.S_IMODE(file_stat.st_mode))[2:].zfill(4),
                "owner": _owner_name(file_stat.st_uid),
                "group": _group_name(file_stat.st_gid),
            }
        )
        with open(path, "rb") as stream:
            content = stream.read()
        result["sha256"] = hashlib.sha256(content).hexdigest()
        if len(content) > max_file_size or b"\x00" in content[:4096]:
            result["is_binary"] = True
            return result
        text = content.decode("utf-8", errors="replace")
        result["lines"] = text.splitlines()
        if parser != "hash":
            result["options"] = _parse_options(text, parser)
    except OSError as error:
        result["error"] = str(error)
    return result


def _read_sysctl(key):
    path = "/proc/sys/" + key.replace(".", "/")
    value = None
    exists = False
    error = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            value = _clean_value(stream.read())
        exists = True
    except OSError as exception:
        error = str(exception)
    return {
        "path": path,
        "exists": exists,
        "value": value,
        "error": error,
    }


def _find_option(file_state, key, section=None, occurrence="first"):
    entries = []
    for option_key, option_entries in file_state.get("options", {}).items():
        if option_key.casefold() != str(key).casefold():
            continue
        for entry in option_entries:
            if section is not None and entry.get("section") != section:
                continue
            entries.append(entry)
    if not entries:
        return None
    values = [entry.get("value") for entry in entries]
    if occurrence == "all":
        return values
    if occurrence == "last":
        return values[-1]
    return values[0]


def _run_command(module, command, timeout, cache):
    if isinstance(command, str):
        command = shlex.split(command)
    cache_key = json.dumps(command, sort_keys=True)
    if cache_key in cache:
        return cache[cache_key]
    try:
        rc, stdout, stderr = module.run_command(
            command,
            check_rc=False,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        result = {
            "command": command,
            "rc": rc,
            "stdout": stdout,
            "stderr": stderr,
            "error": None,
        }
    except Exception as error:  # Ansible raises several command related errors.
        result = {
            "command": command,
            "rc": None,
            "stdout": "",
            "stderr": "",
            "error": str(error),
        }
    cache[cache_key] = result
    return result


def _check_matches(actual, exists, check):
    match = check.get("match", "exact")
    expected = check.get("expected")
    case_sensitive = _as_bool(check.get("case_sensitive", True), True)
    if match == "absent":
        return not exists
    if match == "present":
        return exists
    if not exists:
        return False
    if match == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        values = actual if isinstance(actual, list) else [actual]
        return any(
            re.search(str(expected), str(value), flags=flags) is not None
            for value in values
        )
    if match == "contains":
        values = actual if isinstance(actual, list) else [actual]
        return any(_values_equal(value, expected, case_sensitive) for value in values)
    if match == "contains_all":
        values = actual if isinstance(actual, list) else [actual]
        expected_values = expected if isinstance(expected, list) else [expected]
        return all(
            any(_values_equal(value, item, case_sensitive) for value in values)
            for item in expected_values
        )
    return _values_equal(actual, expected, case_sensitive)


def _normalize_check(raw_check):
    check = dict(raw_check)
    check["type"] = check.get("type", "file")
    check["enabled"] = _as_bool(check.get("enabled", True), True)
    check["match"] = check.get("match", "exact")
    check["case_sensitive"] = _as_bool(check.get("case_sensitive", True), True)
    check["has_expected"] = "expected" in check
    if "id" not in check:
        identifier = [check["type"]]
        if check.get("path"):
            identifier.append(str(check["path"]))
        if check.get("command"):
            identifier.append(str(check["command"]))
        if check.get("key"):
            identifier.append(str(check["key"]))
        check["id"] = ":".join(identifier)
    return check


def _capture_one_check(module, check, files, command_timeout, command_cache):
    record = {
        "id": check["id"],
        "type": check["type"],
        "key": check.get("key"),
        "path": check.get("path"),
        "section": check.get("section"),
        "pattern": check.get("pattern"),
        "expected": check.get("expected"),
        "match": check["match"],
        "case_sensitive": check["case_sensitive"],
        "has_expected": check["has_expected"],
        "exists": False,
        "value": None,
        "error": None,
        "compliant": None,
    }
    check_type = check["type"]
    if check_type == "file":
        path = os.path.expanduser(str(check.get("path", "")))
        record["path"] = path
        file_state = files.get(path)
        if file_state is None:
            record["error"] = "file path is not configured for capture"
        elif not file_state["exists"]:
            record["exists"] = False
            record["error"] = file_state.get("error")
        else:
            record["exists"] = True
            if check.get("key") is None:
                record["value"] = file_state.get("sha256")
            else:
                record["value"] = _find_option(
                    file_state,
                    check["key"],
                    check.get("section"),
                    check.get("occurrence", "first"),
                )
                record["exists"] = record["value"] is not None
    elif check_type == "sysctl":
        sysctl_state = _read_sysctl(str(check["key"]))
        record.update(sysctl_state)
    elif check_type == "line":
        path = os.path.expanduser(str(check.get("path", "")))
        record["path"] = path
        file_state = files.get(path)
        if file_state is None:
            record["error"] = "file path is not configured for capture"
        elif not file_state["exists"]:
            record["error"] = file_state.get("error")
        else:
            pattern = str(check.get("pattern", ""))
            flags = 0 if check["case_sensitive"] else re.IGNORECASE
            matched_lines = [
                line
                for line in file_state.get("lines", [])
                if re.search(pattern, line, flags=flags) is not None
            ]
            if check.get("occurrence", "first") == "all":
                record["value"] = matched_lines
            elif matched_lines:
                record["value"] = matched_lines[-1]
            record["exists"] = bool(matched_lines)
    elif check_type in ("command", "command_status"):
        command_result = _run_command(
            module,
            check.get("command"),
            command_timeout,
            command_cache,
        )
        record["command"] = command_result["command"]
        record["error"] = command_result.get("error")
        if check_type == "command_status":
            record["exists"] = command_result.get("rc") is not None
            record["value"] = command_result.get("rc")
            if command_result.get("error"):
                record["error"] = command_result["error"]
            elif command_result.get("rc") not in (0, None):
                record["error"] = (command_result.get("stderr") or "").strip()[:2048]
        else:
            options = _parse_options(command_result.get("stdout", ""), "keyvalue")
            command_file = {"options": options}
            record["value"] = _find_option(
                command_file,
                check["key"],
                check.get("section"),
                check.get("occurrence", "first"),
            )
            record["exists"] = command_result.get("rc") == 0 and record["value"] is not None
            if command_result.get("rc") not in (0, None):
                record["error"] = (command_result.get("stderr") or "").strip()[:2048]
    else:
        record["error"] = "unsupported check type: %s" % check_type

    if record["has_expected"]:
        record["compliant"] = _check_matches(
            record["value"],
            record["exists"],
            check,
        )
    return record


def _normalize_file_specs(raw_files):
    normalized = []
    for raw_file in raw_files or []:
        if isinstance(raw_file, str):
            spec = {"path": raw_file}
        else:
            spec = dict(raw_file)
        spec["path"] = os.path.expanduser(str(spec.get("path", "")))
        spec["parser"] = spec.get("parser", "auto")
        spec["enabled"] = _as_bool(spec.get("enabled", True), True)
        if spec["path"] and spec["enabled"]:
            normalized.append(spec)
    return normalized


def _capture_snapshot(module, params):
    files = {}
    file_specs = list(params.get("files") or [])
    for expectation in params.get("file_expectations") or []:
        expectation_path = expectation.get("path")
        if expectation_path and not any(
            (item.get("path") if isinstance(item, dict) else item)
            == expectation_path
            for item in file_specs
        ):
            file_specs.append({"path": expectation_path, "parser": "ini"})
    for spec in _normalize_file_specs(file_specs):
        files[spec["path"]] = _read_file(
            spec["path"],
            spec["parser"],
            params["max_file_size"],
        )

    checks = []
    seen_ids = set()
    for raw_check in params.get("checks") or []:
        check = _normalize_check(raw_check)
        if not check["enabled"] or check["id"] in seen_ids:
            continue
        seen_ids.add(check["id"])
        checks.append(check)
    for key, expected in (params.get("sysctl") or {}).items():
        check = _normalize_check(
            {
                "id": "sysctl.%s" % key,
                "type": "sysctl",
                "key": key,
                "expected": expected,
                "case_sensitive": False,
            }
        )
        if check["id"] in seen_ids:
            continue
        seen_ids.add(check["id"])
        checks.append(check)
    for expectation in params.get("file_expectations") or []:
        path = os.path.expanduser(str(expectation.get("path", "")))
        section = expectation.get("section")
        for key, expected in sorted((expectation.get("options") or {}).items()):
            check = _normalize_check(
                {
                    "id": "file:%s:%s:%s" % (path, section or "-", key),
                    "type": "file",
                    "path": path,
                    "section": section,
                    "key": key,
                    "expected": expected,
                    "occurrence": "last",
                    "case_sensitive": False,
                }
            )
            if check["id"] in seen_ids:
                continue
            seen_ids.add(check["id"])
            checks.append(check)

    command_cache = {}
    check_records = []
    for check in checks:
        check_records.append(
            _capture_one_check(
                module,
                check,
                files,
                params["command_timeout"],
                command_cache,
            )
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "files": files,
        "checks": check_records,
    }


def _file_summary(file_state):
    return {
        key: file_state.get(key)
        for key in (
            "path",
            "exists",
            "sha256",
            "size",
            "mode",
            "owner",
            "group",
            "is_symlink",
            "is_binary",
            "error",
        )
    }


def _unified_diff(before_lines, after_lines, path):
    return list(
        difflib.unified_diff(
            before_lines or [],
            after_lines or [],
            fromfile="before:%s" % path,
            tofile="after:%s" % path,
            lineterm="",
        )
    )


def _option_changes(before_file, after_file, tracked_items):
    changes = []
    before_options = before_file.get("options", {}) if before_file else {}
    after_options = after_file.get("options", {}) if after_file else {}
    identities = set()
    for options in (before_options, after_options):
        for key, entries in options.items():
            for entry in entries:
                identities.add((entry.get("section"), key))

    for section, key in sorted(
        identities,
        key=lambda item: ((item[0] or ""), item[1]),
    ):
        option_path = (
            after_file.get("path") if after_file else before_file.get("path")
        )
        if (option_path, str(key).casefold()) in tracked_items:
            continue
        before_values = [
            entry.get("value")
            for entry in before_options.get(key, [])
            if entry.get("section") == section
        ]
        after_values = [
            entry.get("value")
            for entry in after_options.get(key, [])
            if entry.get("section") == section
        ]
        before_value = before_values if len(before_values) != 1 else before_values[0]
        after_value = after_values if len(after_values) != 1 else after_values[0]
        if not before_values and not after_values:
            continue
        if _values_equal(before_value, after_value):
            continue
        changes.append(
            {
                "id": "file:%s:%s:%s"
                % (
                    option_path,
                    section or "-",
                    key,
                ),
                "type": "file",
                "path": option_path,
                "section": section,
                "key": key,
                "before": before_value,
                "after": after_value,
                "expected": None,
                "tracked": False,
            }
        )
    return changes


def _build_role_report(role, before, after, params):
    before_checks = {item["id"]: item for item in before.get("checks", [])}
    after_checks = {item["id"]: item for item in after.get("checks", [])}
    checks = []
    changes = []
    noncompliant = []

    for check_id in sorted(set(before_checks) | set(after_checks)):
        before_check = before_checks.get(check_id, {})
        after_check = after_checks.get(check_id, {})
        changed = not (
            before_check.get("exists") == after_check.get("exists")
            and _values_equal(
                before_check.get("value"),
                after_check.get("value"),
                after_check.get("case_sensitive", True),
            )
        )
        item = {
            "id": check_id,
            "type": after_check.get("type", before_check.get("type")),
            "path": after_check.get("path", before_check.get("path")),
            "key": after_check.get("key", before_check.get("key")),
            "section": after_check.get("section", before_check.get("section")),
            "pattern": after_check.get("pattern", before_check.get("pattern")),
            "expected": after_check.get(
                "expected",
                before_check.get("expected"),
            ),
            "before": before_check.get("value"),
            "after": after_check.get("value"),
            "before_exists": before_check.get("exists", False),
            "after_exists": after_check.get("exists", False),
            "changed": changed,
            "compliant": after_check.get("compliant"),
            "error": after_check.get("error") or before_check.get("error"),
        }
        checks.append(item)
        if changed:
            changes.append(
                {
                    "id": check_id,
                    "type": item["type"],
                    "path": item["path"],
                    "section": item["section"],
                    "pattern": item["pattern"],
                    "key": item["key"],
                    "before": item["before"],
                    "after": item["after"],
                    "before_exists": item["before_exists"],
                    "after_exists": item["after_exists"],
                    "expected": item["expected"],
                    "tracked": True,
                }
            )
        if after_check.get("has_expected") and not after_check.get("compliant"):
            noncompliant.append(
                {
                    "id": check_id,
                    "type": item["type"],
                    "path": item["path"],
                    "section": item["section"],
                    "pattern": item["pattern"],
                    "key": item["key"],
                    "expected": item["expected"],
                    "actual": item["after"],
                    "exists": item["after_exists"],
                    "error": item["error"],
                }
            )

    tracked_items = {
        (str(item["path"]), str(item["key"]).casefold())
        for item in checks
        if item["type"] == "file" and item.get("key") is not None
    }
    file_changes = []
    before_files = before.get("files", {})
    after_files = after.get("files", {})
    for path in sorted(set(before_files) | set(after_files)):
        before_file = before_files.get(path, {})
        after_file = after_files.get(path, {})
        if before_file.get("sha256") == after_file.get("sha256") and before_file.get(
            "exists"
        ) == after_file.get("exists"):
            continue
        path_changes = _option_changes(before_file, after_file, tracked_items)
        changes.extend(path_changes)
        file_changes.append(
            {
                "path": path,
                "before": _file_summary(before_file),
                "after": _file_summary(after_file),
                "diff": _unified_diff(
                    before_file.get("lines", []),
                    after_file.get("lines", []),
                    path,
                ),
            }
        )

    changes.sort(
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("path") or ""),
            str(item.get("section") or ""),
            str(item.get("key") or ""),
            str(item.get("id") or ""),
        )
    )
    noncompliant.sort(key=lambda item: str(item.get("id")))
    summary = {
        "checked": len(checks),
        "changed": len(changes),
        "noncompliant": len(noncompliant),
        "files_changed": len(file_changes),
        "before_noncompliant": sum(
            1
            for item in before.get("checks", [])
            if item.get("has_expected") and not item.get("compliant")
        ),
    }
    return {
        "role": role,
        "baseline": {
            "before": {
                path: _file_summary(state)
                for path, state in sorted(before_files.items())
            },
            "after": {
                path: _file_summary(state)
                for path, state in sorted(after_files.items())
            },
        },
        "changes": changes,
        "file_changes": file_changes,
        "noncompliant": noncompliant,
        "checks": checks,
        "summary": summary,
    }


def _read_report(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            report = json.load(stream)
        return report if isinstance(report, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_report(path, report):
    content = json.dumps(
        report,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"
    previous = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as stream:
                previous = stream.read()
        except OSError:
            previous = None
    if previous == content:
        return False

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".hardening-audit-",
        dir=directory,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.chmod(temporary_path, 0o640)
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
    return True


def _merge_report(base, role_report, params):
    roles = dict(base.get("roles") or {})
    roles[role_report["role"]] = role_report
    aggregate_changes = []
    aggregate_noncompliant = []
    aggregate_file_changes = []
    for role_name in sorted(roles):
        section = roles[role_name]
        for change in section.get("changes", []):
            item = dict(change)
            item["role"] = role_name
            aggregate_changes.append(item)
        for item in section.get("noncompliant", []):
            noncompliant = dict(item)
            noncompliant["role"] = role_name
            aggregate_noncompliant.append(noncompliant)
        for item in section.get("file_changes", []):
            file_change = dict(item)
            file_change["role"] = role_name
            aggregate_file_changes.append(file_change)
    summary = {
        "roles": len(roles),
        "checked": sum(
            section.get("summary", {}).get("checked", 0)
            for section in roles.values()
        ),
        "changed": len(aggregate_changes),
        "noncompliant": len(aggregate_noncompliant),
        "files_changed": len(aggregate_file_changes),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "collection": COLLECTION_NAME,
        "host": params.get("host") or "",
        "distribution": params.get("distribution") or "",
        "distribution_version": params.get("distribution_version") or "",
        "os_family": params.get("os_family") or "",
        "roles": roles,
        "changes": aggregate_changes,
        "file_changes": aggregate_file_changes,
        "noncompliant": aggregate_noncompliant,
        "summary": summary,
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(type="str", required=True, choices=["capture", "compare"]),
            role=dict(type="str", required=True),
            files=dict(type="list", elements="raw", default=[]),
            checks=dict(type="list", elements="dict", default=[]),
            sysctl=dict(type="dict", default={}),
            file_expectations=dict(type="list", elements="dict", default=[]),
            before=dict(type="dict"),
            report_file=dict(
                type="str",
                default="/var/log/devsec-hardening/hardening-baseline.json",
            ),
            fail_on_noncompliance=dict(type="bool", default=False),
            host=dict(type="str", default=""),
            distribution=dict(type="str", default=""),
            distribution_version=dict(type="str", default=""),
            os_family=dict(type="str", default=""),
            command_timeout=dict(type="int", default=30),
            max_file_size=dict(type="int", default=2097152),
        ),
        supports_check_mode=True,
    )

    params = module.params
    if params["action"] == "capture":
        snapshot = _capture_snapshot(module, params)
        module.exit_json(changed=False, snapshot=snapshot)

    if not params.get("before"):
        module.fail_json(msg="before is required when action is compare")

    after = _capture_snapshot(module, params)
    role_report = _build_role_report(
        params["role"],
        params["before"],
        after,
        params,
    )
    current_role_report = role_report
    report = _merge_report({}, current_role_report, params)
    report_path = params.get("report_file")
    report_changed = False
    if report_path and not module.check_mode:
        base = _read_report(report_path)
        existing_role = (base.get("roles") or {}).get(params["role"])
        existing_expectations = {
            item.get("id"): item.get("expected")
            for item in (existing_role or {}).get("checks", [])
        }
        current_expectations = {
            item.get("id"): item.get("expected")
            for item in current_role_report.get("checks", [])
        }
        preserve_existing = (
            not role_report["changes"]
            and existing_role is not None
            and role_report["noncompliant"] == existing_role.get("noncompliant")
            and role_report["summary"].get("checked")
            == existing_role.get("summary", {}).get("checked")
            and current_expectations == existing_expectations
        )
        if preserve_existing:
            report = _merge_report(base, existing_role, params)
        else:
            report = _merge_report(base, current_role_report, params)
            report_changed = _write_report(report_path, report)

    result = {
        "changed": report_changed,
        "role": params["role"],
        "report_file": report_path,
        "report": report,
        "changes": current_role_report["changes"],
        "file_changes": current_role_report["file_changes"],
        "noncompliant": current_role_report["noncompliant"],
        "checks": current_role_report["checks"],
        "summary": current_role_report["summary"],
    }
    if params["fail_on_noncompliance"] and current_role_report["noncompliant"]:
        module.fail_json(
            msg="%s hardening has %s noncompliant item(s)"
            % (params["role"], len(current_role_report["noncompliant"])),
            **result
        )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
