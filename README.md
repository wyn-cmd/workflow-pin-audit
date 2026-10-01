# workflow-pin-audit

Finds the GitHub Actions supply chain mistakes that turn up over and over in real repositories, starting with action references that are pinned to a mutable tag instead of a commit SHA.

A line like `uses: actions/checkout@v4` trusts a tag. Tags move. Whoever holds the upstream repository, or whoever manages to compromise it, can point `v4` at a different commit and your next run executes that code with your token, your secrets and your runner. In 2025 the tj-actions/changed-files tag swap exposed more than 15,000 repositories that way, and 2026 has kept the pattern going. Pinning to a full 40 character commit SHA closes that path, and it is a mechanical fix once you know which lines to change. This tool prints that list.

It also flags container references without a digest, the `pull_request_target` trigger, `write-all` token permissions, workflows with no top level `permissions` block, and untrusted event fields interpolated straight into a shell step.

No third party packages, no network calls, no configuration. Python 3.7 or newer.

## Usage

```
python3 workflow_pin_audit.py                     # scan the current directory
python3 workflow_pin_audit.py path/to/repo        # scan one repository
python3 workflow_pin_audit.py .github/workflows/ci.yml
python3 workflow_pin_audit.py --json              # machine readable output
python3 workflow_pin_audit.py --fail-on medium    # fail the run on medium findings too
python3 workflow_pin_audit.py --list-checks       # print the check list
```

When the argument is a directory the tool walks it and keeps only files under `.github/workflows/`, so unrelated compose files and other YAML elsewhere in the tree stay out of the report.

## What it checks

| Check | Severity | Meaning |
| --- | --- | --- |
| WPA001 | high | An action or reusable workflow reference is not pinned to a full commit SHA. Local references such as `./.github/actions/setup` are ignored. |
| WPA002 | high | A `docker://` reference has no `@sha256:` digest. |
| WPA003 | medium | The workflow runs on `pull_request_target`, which gives fork pull requests a token in the base repository context. |
| WPA004 | medium | A `permissions` block is set to `write-all`. |
| WPA005 | low | The workflow has no top level `permissions` block, so the token scope depends on repository settings. |
| WPA006 | high | A value an outside user controls, such as `github.event.pull_request.title`, is interpolated into a `run` step, which allows command injection. |

## Example output

```
examples/unsafe-workflow.yml
     6  MEDIUM  WPA003  workflow uses the pull_request_target trigger
        pull_request_target:
     8  MEDIUM  WPA004  workflow or job grants write-all token permissions
        permissions: write-all
    14  HIGH    WPA001  action reference is not pinned to a full commit SHA
        actions/checkout@v4
    15  HIGH    WPA002  container image reference is not pinned to a sha256 digest
        docker://alpine:3.20
    18  HIGH    WPA006  untrusted context value is interpolated into a run step
        echo "hello ${{ github.event.pull_request.title }}"

5 findings in 1 workflow files (3 high, 2 medium, 0 low)
```

`examples/unsafe-workflow.yml` in this repository produces exactly that output. Run the tool against it to check your copy behaves the same way.

With `--json` the same run prints a single object with `workflows_scanned`, a `summary` count per severity and a `findings` array where each entry carries `file`, `line`, `check`, `severity`, `message` and `evidence`.

## Exit codes

- `0` no finding at or above the `--fail-on` severity
- `1` at least one finding at or above the `--fail-on` severity
- `2` usage problem, unreadable file, or no workflow files under the given path

The default threshold is `high`, so an unpinned action fails the run while a missing `permissions` block does not. `--fail-on never` always exits `0`, which is useful for a first report before you decide to enforce anything.

## Using it as a CI gate

```yaml
name: workflow audit
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  pin-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"
      - run: |
          git clone --depth 1 https://github.com/wyn-cmd/workflow-pin-audit tools/workflow-pin-audit
          python3 tools/workflow-pin-audit/workflow_pin_audit.py .
```

## Limitations

The scanner is line based rather than a YAML parser, so it does not follow anchors, aliases or multi document files, and a workflow written in an unusual layout can slip past it. It reports what a reviewer needs to look at; it does not contact GitHub to confirm that a SHA exists or belongs to the action it appears next to. A pinned SHA is reported as clean even if the commit it points at is malicious, because pinning only stops the reference from moving after review.

## Tests

```
python3 -m unittest discover -s tests -v
```

The suite covers each check with both a positive and a negative case, including the block scalar handling that decides whether an interpolation sits inside a `run` step, and it drives the command line end to end to confirm the exit codes and the JSON shape.

## License

MIT, see `LICENSE`.
