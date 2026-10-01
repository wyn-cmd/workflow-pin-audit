# Tests for workflow_pin_audit. Run them from the repository root with
# python3 -m unittest discover -s tests -v

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import workflow_pin_audit as wpa  # noqa: E402

PINNED_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"

BASE_HEADER = "name: ci\non:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"


def workflow(body, header=None):
    return (header if header is not None else BASE_HEADER) + body


def checks_for(text):
    return [finding.check for finding in wpa.scan_text(text, "ci.yml")]


class PinChecks(unittest.TestCase):
    def test_tag_reference_is_flagged(self):
        text = workflow("      - uses: actions/checkout@v4\n")
        self.assertIn("WPA001", checks_for(text))

    def test_sha_reference_is_clean_of_pin_findings(self):
        text = workflow("      - uses: actions/checkout@%s\n" % PINNED_SHA)
        self.assertNotIn("WPA001", checks_for(text))

    def test_sha_reference_with_version_comment_is_clean(self):
        text = workflow("      - uses: actions/checkout@%s # v4.2.2\n" % PINNED_SHA)
        self.assertNotIn("WPA001", checks_for(text))

    def test_uppercase_sha_is_not_accepted(self):
        text = workflow("      - uses: actions/checkout@%s\n" % PINNED_SHA.upper())
        self.assertIn("WPA001", checks_for(text))

    def test_reference_without_a_ref_is_flagged(self):
        text = workflow("      - uses: actions/checkout\n")
        self.assertIn("WPA001", checks_for(text))

    def test_local_action_is_skipped(self):
        text = workflow("      - uses: ./.github/actions/setup\n")
        self.assertNotIn("WPA001", checks_for(text))

    def test_reusable_workflow_call_is_flagged(self):
        text = workflow("      - uses: owner/repo/.github/workflows/build.yml@main\n")
        self.assertIn("WPA001", checks_for(text))

    def test_docker_image_needs_a_digest(self):
        tagged = workflow("      - uses: docker://alpine:3.20\n")
        self.assertIn("WPA002", checks_for(tagged))
        digest = "sha256:" + ("a" * 64)
        digested = workflow("      - uses: docker://alpine@%s\n" % digest)
        self.assertNotIn("WPA002", checks_for(digested))


class TriggerAndPermissionChecks(unittest.TestCase):
    def test_pull_request_target_key_is_flagged(self):
        header = "on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
        text = workflow("      - run: echo hi\n", header=header)
        self.assertIn("WPA003", checks_for(text))

    def test_pull_request_target_list_entry_is_flagged(self):
        header = "on:\n  - pull_request_target\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
        text = workflow("      - run: echo hi\n", header=header)
        self.assertIn("WPA003", checks_for(text))

    def test_write_all_is_flagged(self):
        header = "on:\n  push:\npermissions: write-all\njobs:\n  build:\n    steps:\n"
        text = workflow("      - run: echo hi\n", header=header)
        self.assertIn("WPA004", checks_for(text))

    def test_missing_permissions_block_is_reported(self):
        header = "on:\n  push:\njobs:\n  build:\n    steps:\n"
        text = workflow("      - run: echo hi\n", header=header)
        self.assertIn("WPA005", checks_for(text))

    def test_present_permissions_block_is_not_reported(self):
        text = workflow("      - run: echo hi\n")
        self.assertNotIn("WPA005", checks_for(text))


class InjectionChecks(unittest.TestCase):
    def test_untrusted_context_inside_run_block_is_flagged(self):
        body = "      - run: |\n          echo \"${{ github.event.pull_request.title }}\"\n"
        self.assertIn("WPA006", checks_for(workflow(body)))

    def test_untrusted_context_in_inline_run_is_flagged(self):
        body = "      - run: echo ${{ github.head_ref }}\n"
        self.assertIn("WPA006", checks_for(workflow(body)))

    def test_untrusted_context_outside_a_run_block_is_not_reported(self):
        body = "      - name: ${{ github.event.issue.title }}\n        uses: actions/checkout@%s\n" % PINNED_SHA
        self.assertNotIn("WPA006", checks_for(workflow(body)))

    def test_step_output_inside_run_block_is_not_flagged(self):
        body = "      - run: |\n          echo \"${{ steps.build.outputs.version }}\"\n"
        self.assertNotIn("WPA006", checks_for(workflow(body)))


class CliChecks(unittest.TestCase):
    def make_tree(self, body):
        directory = tempfile.mkdtemp()
        workflow_dir = os.path.join(directory, ".github", "workflows")
        os.makedirs(workflow_dir)
        with open(os.path.join(workflow_dir, "ci.yml"), "w", encoding="utf-8") as handle:
            handle.write(body)
        return directory

    def run_cli(self, directory, *extra):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "workflow_pin_audit.py"), directory] + list(extra),
            capture_output=True,
            text=True,
        )

    def test_clean_workflow_exits_zero(self):
        body = workflow("      - uses: actions/checkout@%s\n      - run: echo ok\n" % PINNED_SHA)
        result = self.run_cli(self.make_tree(body))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_findings_exit_one(self):
        result = self.run_cli(self.make_tree(workflow("      - uses: actions/checkout@v4\n")))
        self.assertEqual(result.returncode, 1)

    def test_fail_on_never_exits_zero(self):
        result = self.run_cli(self.make_tree(workflow("      - uses: actions/checkout@v4\n")), "--fail-on", "never")
        self.assertEqual(result.returncode, 0)

    def test_json_output_lists_findings(self):
        result = self.run_cli(self.make_tree(workflow("      - uses: actions/checkout@v4\n")), "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["workflows_scanned"], 1)
        self.assertIn("WPA001", [item["check"] for item in payload["findings"]])

    def test_missing_workflow_directory_exits_two(self):
        result = self.run_cli(tempfile.mkdtemp())
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
