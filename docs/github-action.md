# Ardvane in GitHub Actions

Ardvane on your computer protects what *you* clone, open, install and push. Your teammates' machines and the branches
nobody opens locally (dependabot branches, old feature branches) need a check that runs on GitHub itself. In the
October 2026 incident, 19 of 24 infected branches in one organization were branches nobody had open.

The Ardvane Action runs the same read-only scanner on GitHub's servers. Nothing from your repository is ever run.

## On every push and pull request

Add `.github/workflows/ardvane.yml`:

```yaml
name: ardvane
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Abdul-Moiz31/ardvane@v0.3.0
```

Malware fails the check and appears on the exact file in the pull request, with a summary of what to do. Make the
check **required** (Settings → Rules → your branch ruleset → Require status checks) and infected code can't be merged.

## Every branch, every night

```yaml
name: ardvane-nightly
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: Abdul-Moiz31/ardvane@v0.3.0
        with:
          mode: all-branches
```

No checkout is needed: every branch is downloaded through the GitHub API, scanned and deleted.

## Your whole organization

Run the nightly job in one repository and list the others. The default token can only read the repository the
workflow runs in, so give it a [fine-grained token](https://github.com/settings/personal-access-tokens) with
**read-only** access to the repositories' **contents**, saved as a secret:

```yaml
      - uses: Abdul-Moiz31/ardvane@v0.3.0
        with:
          mode: all-branches
          token: ${{ secrets.ARDVANE_READ_TOKEN }}
          repositories: |
            my-org/api
            my-org/web
            my-org/docs
```

## Options

| Input | Default | |
|---|---|---|
| `mode` | `checkout` | `checkout`: the checked-out code. `all-branches`: every branch through the API. |
| `fail-on` | `danger` | Fail on `danger`, on `warning` as well, or `never`. |
| `repositories` | | `all-branches` only: more repositories, one per line (`owner/name` or a link). |
| `token` | `github.token` | Token for the GitHub API. |
| `update-detections` | `true` | Fetch Ardvane's signed detection list first, or use the built-in detections only. |

Outputs: `danger` and `warnings` (numbers of findings), for later steps.

## Trust

- **Pin it.** Use a release tag (`@v0.3.0`) or, stricter, the release's commit hash. Releases are signed and only made
  by Ardvane's release workflow on `main`.
- **Read-only.** The scanner only reads files and runs git with its hooks and `core.fsmonitor` turned off. File names
  from the scanned repository are escaped before they reach the job log, so a crafted name can't inject workflow
  commands.
- **Minimal permissions.** `contents: read` is all it needs.
