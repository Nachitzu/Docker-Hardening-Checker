# Docker Hardening Checker

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/nacho/Docker-Hardening-Checker/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![Tests](https://img.shields.io/badge/tests-125%20passing-brightgreen)](tests/)

A small web app + CLI + GitHub Action that analyzes `Dockerfile` and
`docker-compose.yml` files and flags common security bad practices:
root user, exposed sensitive ports, secrets in `ENV` / `ARG` /
`environment`, unpinned images, privileged containers, Docker socket
mounts, dangerous capabilities, `curl | sh`, and more.

Three entry points, one engine:

| Use case | How |
|---|---|
| Browse / edit interactively | `python app.py` -> <http://127.0.0.1:5000> |
| Run locally or in any CI | `python cli.py [paths...]` |
| Use as a GitHub Action | see [GitHub Action](#github-action) below |

## Why use it over Hadolint / Trivy / Dockle?

Honest comparison with the popular tools in the same space. "Static
config" = analyzing a Dockerfile / compose file as text. "Image scan" =
inspecting a built image's layers and metadata.

| Capability | **Docker Hardening Checker** | [Hadolint](https://github.com/hadolint/hadolint) | [Trivy](https://github.com/aquasecurity/trivy) | [Dockle](https://github.com/goodwithtech/dockle) |
|---|---|---|---|---|
| Dockerfile linting | Yes | Yes (de-facto standard) | Partial | No |
| `docker-compose.yml` linting | **Yes** (19 rules) | No | Partial (misconfig) | No |
| Web UI for browsing findings | **Yes** | No | No | No |
| CLI | Yes | Yes | Yes | Yes |
| GitHub Action | **Yes (composite)** | Yes (third-party) | Yes (official) | Yes (third-party) |
| SARIF output for code scanning | **Yes** | No | Yes | No |
| CVE / package vulnerability scan | No | No | **Yes** | Yes |
| Built image inspection | No | No | **Yes** | **Yes** |
| Custom rule authoring | Edit `app.py` | YAML rules | YAML rules | Limited |
| Runtime requirements | Python 3.10+ | Haskell binary | Go binary | Go binary |
| Offline / no network | **Yes** | Yes | Partial | Yes |

**When to use this tool** — Dockerfile + docker-compose hardening as a
fast pre-commit / pre-merge check, especially in monorepos where every
service has its own compose file. The UI is useful for code review and
onboarding.

**When NOT to use it** — production vulnerability scanning of built
images. Use [Trivy](https://github.com/aquasecurity/trivy) or
[Dockle](https://github.com/goodwithtech/dockle) for that. They check
what's *inside* the image (CVEs, secrets in layers, setuid binaries);
we check what the Dockerfile/compose file *says*.

The two are complementary. Many teams run Hadolint + this tool on PRs
and Trivy on the built image in a separate job.

## Run the web UI

```bash
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. Paste a file, drop one on the editor, or
hit **Load sample** to try a pre-baked vulnerable file.

## Run the CLI

```bash
python cli.py                              # scan the current directory
python cli.py Dockerfile docker-compose.yml
python cli.py services/*/Dockerfile --recursive
python cli.py . --format json
python cli.py . --format sarif --output hardening.sarif
python cli.py . --fail-on critical         # only fail on critical findings
python cli.py . --ignore DF-010 --ignore DC-011
```

When run inside a GitHub Actions runner the default format is
`github`, which emits `::error` / `::warning` / `::notice` workflow
commands and appends a markdown report to `$GITHUB_STEP_SUMMARY`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above `--fail-on` (default: `high`) |
| `1`  | At least one finding at or above `--fail-on` |
| `2`  | Tool error (e.g. no files matched) |

### Output formats

| Format | Use it for |
|---|---|
| `text`   | Terminal output, with ANSI colors when stdout is a TTY. |
| `json`   | Machine-readable, stable schema. `{"files": [...], "totals": {...}}`. |
| `sarif`  | SARIF 2.1.0. Upload to GitHub code scanning with `github/codeql-action/upload-sarif@v3`. |
| `github` | `::error` / `::warning` / `::notice` annotations + markdown step summary. |

## GitHub Action

This repo is also a composite GitHub Action. From any workflow:

```yaml
- uses: actions/checkout@v4
- uses: ./
  with:
    paths: '.'                # files, directories, or globs (space-separated)
    fail-on: high             # critical|high|medium|low|info
    format: github            # text|json|sarif|github
    ignore: 'DF-010,DC-011'   # optional, comma-separated rule ids
```

Outputs:

```yaml
- id: harden
  uses: ./
  with: { fail-on: high }

- run: echo "Found ${{ harden.outputs.critical }} critical and ${{ harden.outputs.high }} high"
```

### Example workflow

See `.github/workflows/hardening.yml` for a copy-paste example, and
`.github/workflows/ci.yml` for the workflow that tests, lints,
type-checks, and dogfoods this very repo.

## What it checks

### Dockerfile rules (`app.py` -> `analyze_dockerfile`)

| ID        | Severity | Rule |
|-----------|----------|------|
| DF-001    | high     | Base image without a specific tag |
| DF-001b   | high     | Base image without any tag (resolves to `:latest`) |
| DF-002    | critical | No `USER` directive (container runs as root) |
| DF-002b   | critical | `USER root` / `USER 0` |
| DF-003    | high     | `RUN` after `USER` (installs run as the unprivileged user) |
| DF-004-ENV| critical | Likely secret value in `ENV KEY=...` |
| DF-004-ARG| critical | Likely secret value in `ARG KEY=...` |
| DF-005    | low      | `ADD` used for plain local files (use `COPY`) |
| DF-006    | high     | `curl ... | sh` / `wget ... | sh` |
| DF-007    | low      | `apt-get install` without `--no-install-recommends` |
| DF-007b   | low      | apt cache not cleaned in the same `RUN` |
| DF-008    | low      | No `HEALTHCHECK` |
| DF-009    | high     | `EXPOSE` of a sensitive management port (22, 23, 25, 3389, ...) |
| DF-010    | medium   | `COPY . .` ships the whole build context |
| DF-011    | low      | `WORKDIR` is relative instead of absolute |

### docker-compose rules (`app.py` -> `analyze_compose`)

| ID             | Severity | Rule |
|----------------|----------|------|
| DC-VER         | info     | Legacy `version: 2.x` compose file |
| DC-001         | high     | Service with no `image` and no `build` |
| DC-002         | high     | Unpinned image (no tag / `:latest`) |
| DC-003         | critical | `privileged: true` |
| DC-004         | high     | Dangerous `cap_add` (`SYS_ADMIN`, `NET_ADMIN`, `ALL`, ...) |
| DC-005         | low      | No `cap_drop: [ALL]` baseline |
| DC-006         | high     | `network_mode: host` |
| DC-007         | high     | `pid: host` |
| DC-008         | medium   | `ipc: host` |
| DC-009         | critical | No `user:` set (container runs as root) |
| DC-010         | critical | Explicit `user: root` / `user: 0` |
| DC-011         | low      | `read_only: true` not set |
| DC-012         | critical | Likely secret in `environment:` |
| DC-013         | medium   | `env_file:` references `.env` |
| DC-014         | critical | Sensitive port published on `0.0.0.0` |
| DC-015         | critical | Sensitive host bind mount (`/`, `/etc`, `/proc`, ...) |
| DC-016         | critical | Docker socket mounted into the container |
| DC-017         | info     | `restart: always` with no pinned image |
| DC-SECRET-...  | medium   | Inline `secrets:` entry (not external) |

## Project layout

```
.
+- app.py                  # Flask app + analysis rules
+- cli.py                  # CLI / GitHub Action entry point
+- action.yml              # composite action definition
+- pyproject.toml          # package metadata + ruff/mypy/pytest config
+- LICENSE                 # MIT
+- SECURITY.md             # vulnerability disclosure policy
+- requirements.txt
+- Makefile
+- tests/                  # pytest suite (125 tests, 90%+ coverage)
|  +- conftest.py
|  +- test_dockerfile_rules.py
|  +- test_compose_rules.py
|  +- test_cli.py
|  +- test_api.py
+- templates/
|  +- index.html
+- static/
|  +- style.css
|  +- app.js
+- samples/                # intentionally vulnerable test fixtures
|  +- Dockerfile.bad
|  +- Dockerfile.good
|  +- compose-bad.yml
|  +- compose-good.yml
+- .github/
   +- workflows/
      +- ci.yml            # tests + lint + types + dogfooding + enforce
      +- hardening.yml     # example of using the action from another repo
```

## Extending

Every rule is a small block inside `analyze_dockerfile` or
`analyze_compose` in `app.py`. Each `Finding(rule_id, title, severity,
description, remediation, line, snippet)` shows up directly in the
web UI, the CLI, the GitHub Action annotations, and the SARIF output.
Add a new block, restart the server (or just rerun the CLI), that's it.
A test in `tests/test_dockerfile_rules.py` or
`tests/test_compose_rules.py` will lock the rule in.

The Dockerfile parser handles line continuations and comments. If you
need more exotic syntax (heredocs, multi-stage `AS`, build args in
`FROM`), extend `parse_dockerfile` rather than writing more regexes.

## Local development

```bash
make install         # pip install -e ".[dev]"
make test            # pytest with coverage (must stay >= 70%)
make lint            # ruff
make types           # mypy
make web             # run the UI on :5000
make sample          # scan samples/ with the CLI
```

## Security

See [SECURITY.md](SECURITY.md) for the supported-versions table and
how to report a vulnerability privately.
