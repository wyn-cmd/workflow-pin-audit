#!/usr/bin/env python3
# workflow_pin_audit reads GitHub Actions workflow files and reports supply chain
# risks that a reviewer can act on. It is deliberately dependency free so it can
# run inside any CI container with nothing but a Python interpreter.

import argparse
import json
import os
import re
import sys

CHECK_INFO = {
    "WPA001": ("high", "action reference is not pinned to a full commit SHA"),
    "WPA002": ("high", "container image reference is not pinned to a sha256 digest"),
    "WPA003": ("medium", "workflow uses the pull_request_target trigger"),
    "WPA004": ("medium", "workflow or job grants write-all token permissions"),
    "WPA005": ("low", "workflow has no top level permissions block"),
    "WPA006": ("high", "untrusted context value is interpolated into a run step"),
}

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

# Context values that a pull request author, issue author or dispatch caller can
# set to arbitrary text. Interpolating them into a shell step lets that text run
# as a command in the runner.
UNTRUSTED_CONTEXTS = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits[0].message",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.head_ref",
    "inputs.",
)

USES_RE = re.compile(r"^(\s*)(?:-\s+)?uses:\s*(.*)$")
RUN_RE = re.compile(r"^(\s*)(?:-\s+)?run:(\s*)(.*)$")
PERM_RE = re.compile(r"^(\s*)(?:-\s+)?permissions:(\s*)(.*)$")
PRT_KEY_RE = re.compile(r"^\s*(?:-\s+)?pull_request_target:\s*$")
PRT_LIST_RE = re.compile(r"^\s*-\s*pull_request_target\s*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}


class Finding(object):
    # One reported problem: where it is, which check raised it and the raw text.
    def __init__(self, file_path, line_number, check, evidence):
        self.file_path = file_path
        self.line_number = line_number
        self.check = check
        self.severity = CHECK_INFO[check][0]
        self.message = CHECK_INFO[check][1]
        self.evidence = evidence.strip()

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


def strip_comment(value):
    # Workflow values are plain scalars in practice, so the first hash starts a
    # comment. This drops trailing notes such as a version marker after a SHA.
    return value.split("#", 1)[0].strip()


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def collect_run_block_lines(lines):
    # Returns the zero based indexes of every line that is the body of a run
    # step. A run key either carries an inline command or introduces a block
    # scalar whose body sits on the more indented lines below it.
    in_block_indent = None
    block_lines = set()
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        indent = indent_of(line)
        if in_block_indent is not None and indent > in_block_indent:
            block_lines.add(index)
            continue
        in_block_indent = None
        match = RUN_RE.match(line)
        if not match:
            continue
        key_indent = len(match.group(1))
        remainder = match.group(3).strip()
        if remainder and not remainder.startswith("|") and not remainder.startswith(">"):
            block_lines.add(index)
        else:
            in_block_indent = key_indent
    return block_lines


def classify_uses(ref):
    # Returns the check id that applies to a uses value, or None when the
    # reference is either local to the repository or immutably pinned.
    if not ref:
        return "WPA001"
    if ref.startswith("./") or ref.startswith("../"):
        return None
    if ref.startswith("docker://"):
        if "@sha256:" in ref:
            return None
        return "WPA002"
    if "@" not in ref:
        return "WPA001"
    pin = ref.rsplit("@", 1)[1].strip()
    if SHA_RE.match(pin):
        return None
    return "WPA001"


def scan_text(text, display_path):
    # Scans one workflow file and returns findings ordered by line number.
    lines = text.splitlines()
    run_lines = collect_run_block_lines(lines)
    findings = []
    has_permissions_block = False

    for index, line in enumerate(lines):
        number = index + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if index in run_lines:
            continue

        permission_match = PERM_RE.match(line)
        if permission_match:
            if len(permission_match.group(1)) == 0:
                has_permissions_block = True
            value = strip_comment(permission_match.group(3))
            if "write-all" in value:
                findings.append(Finding(display_path, number, "WPA004", stripped))
            continue

        uses_match = USES_RE.match(line)
        if uses_match:
            ref = strip_comment(uses_match.group(2))
            check = classify_uses(ref)
            if check:
                findings.append(Finding(display_path, number, check, ref or stripped))
            continue

        if PRT_KEY_RE.match(line) or PRT_LIST_RE.match(line):
            findings.append(Finding(display_path, number, "WPA003", stripped))
            continue

    for index in sorted(run_lines):
        line = lines[index]
        if "${{" not in line:
            continue
        for token in UNTRUSTED_CONTEXTS:
            if token in line:
                findings.append(Finding(display_path, index + 1, "WPA006", line.strip()))
                break

    if not has_permissions_block:
        findings.append(Finding(display_path, 1, "WPA005", "no top level permissions key"))

    findings.sort(key=lambda item: (item.line_number, item.check))
    return findings


def find_workflow_files(root):
    # Walks a directory tree and keeps only files inside a workflows folder so
    # an unrelated compose or CI file elsewhere in the tree is not reported.
    if os.path.isfile(root):
        return [root]
    found = []
    for current, directories, files in os.walk(root):
        directories[:] = [name for name in directories if name not in SKIP_DIRECTORIES]
        for name in sorted(files):
            if not name.endswith((".yml", ".yaml")):
                continue
            full_path = os.path.join(current, name)
            normalised = full_path.replace(os.sep, "/")
            if "/.github/workflows/" in normalised:
                found.append(full_path)
    return sorted(found)


def display_name(path, root):
    # Prefer a path relative to the scan root so CI logs stay readable.
    if os.path.isdir(root):
        try:
            return os.path.relpath(path, root)
        except ValueError:
            return path
    return path


def scan_paths(paths):
    findings = []
    scanned = 0
    for path in paths:
        for workflow in find_workflow_files(path):
            try:
                with open(workflow, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError as error:
                print("cannot read %s: %s" % (workflow, error), file=sys.stderr)
                return None, None
            scanned += 1
            findings.extend(scan_text(text, display_name(workflow, path)))
    return scanned, findings


def summarise(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] += 1
    counts["total"] = len(findings)
    return counts


def print_report(findings, counts, scanned):
    if findings:
        current_file = None
        for finding in findings:
            if finding.file_path != current_file:
                current_file = finding.file_path
                print(current_file)
            print("  %4d  %-6s  %s  %s" % (finding.line_number, finding.severity.upper(), finding.check, finding.message))
            if finding.evidence:
                print("        %s" % finding.evidence)
        print("")
    print("%d findings in %d workflow files (%d high, %d medium, %d low)" % (counts["total"], scanned, counts["high"], counts["medium"], counts["low"]))


def list_checks():
    for check in sorted(CHECK_INFO):
        severity, message = CHECK_INFO[check]
        print("%s  %-6s  %s" % (check, severity.upper(), message))


def build_parser():
    parser = argparse.ArgumentParser(prog="workflow_pin_audit", description="Check GitHub Actions workflows for supply chain risks.")
    parser.add_argument("paths", nargs="*", default=["."], help="repository root or workflow file (default: current directory)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high", help="lowest severity that makes the process exit non zero")
    parser.add_argument("--list-checks", action="store_true", help="print the checks and exit")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_checks:
        list_checks()
        return 0

    paths = args.paths or ["."]
    scanned, findings = scan_paths(paths)
    if scanned is None:
        return 2

    counts = summarise(findings)

    if not scanned:
        print("no workflow files found under: %s" % ", ".join(paths), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"workflows_scanned": scanned, "summary": counts, "findings": [item.to_dict() for item in findings]}, indent=2))
    else:
        print_report(findings, counts, scanned)

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    for finding in findings:
        if SEVERITY_RANK[finding.severity] >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
