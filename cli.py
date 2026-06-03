"""
Docker Hardening Checker — CLI / GitHub Action entry point.

Reuses the same analysis engine as the web UI (see `app.py`).

Examples
--------
    # Scan everything in the current directory
    python cli.py

    # Scan specific files / globs
    python cli.py Dockerfile docker-compose.yml services/*/Dockerfile

    # JSON output for piping
    python cli.py --format json

    # GitHub Actions annotations + step summary
    python cli.py --format github

    # SARIF for GitHub code scanning (upload with github/codeql-action/upload-sarif)
    python cli.py --format sarif --output hardening.sarif

    # Fail the build only on critical
    python cli.py --fail-on critical
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path

# Reuse the engine from the web app. Importing app is safe — it does not start
# a server on import, only registers routes.
from app import _guess_kind, analyze_compose, analyze_dockerfile

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

DEFAULT_DOCKERFILE_NAMES = ("Dockerfile", "Dockerfile.*", "*.dockerfile")
DEFAULT_COMPOSE_GLOBS = (
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.*.yml", "docker-compose.*.yaml",
    "docker-compose-*.yml", "docker-compose-*.yaml",
    "compose.yml", "compose.yaml",
    "compose.*.yml", "compose.*.yaml",
    "compose-*.yml", "compose-*.yaml",
)

GITHUB_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}

SEVERITY_BADGE = {
    "critical": "\033[1;31mCRITICAL\033[0m",
    "high": "\033[1;33mHIGH\033[0m",
    "medium": "\033[1;33mMEDIUM\033[0m",
    "low": "\033[36mLOW\033[0m",
    "info": "\033[34mINFO\033[0m",
}


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def discover(paths: Iterable[str], recursive: bool) -> list[Path]:
    """Resolve a mix of file paths, directory paths, and glob patterns into a
    list of concrete files to scan, in stable order."""
    seen: set[Path] = set()
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if p not in seen:
                seen.add(p)
                out.append(p)
            continue
        if p.is_dir():
            for f in _scan_dir(p, recursive):
                if f not in seen:
                    seen.add(f)
                    out.append(f)
            continue
        # Glob pattern — relative or absolute
        matches = sorted(p.parent.glob(p.name)) if p.parent.exists() else []
        for m in matches:
            if m.is_file() and m not in seen:
                seen.add(m)
                out.append(m)
    return out


def _scan_dir(root: Path, recursive: bool) -> list[Path]:
    """Look for Dockerfiles and compose files under `root`."""
    matches: list[Path] = []
    iter_dirs = root.rglob("*") if recursive else root.glob("*")
    for f in iter_dirs:
        if not f.is_file():
            continue
        name = f.name
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile") or any(fnmatch.fnmatch(name, g) for g in DEFAULT_COMPOSE_GLOBS):
            matches.append(f)
    return sorted(matches)


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

def scan_file(path: Path) -> dict:
    """Analyze a single file and return a dict with target, filename, summary,
    findings, and any parse warning."""
    text = path.read_text(encoding="utf-8", errors="replace")
    kind = _guess_kind(path.name, text) or "dockerfile"
    if kind == "dockerfile":
        result = analyze_dockerfile(text)
        payload = {"filename": path.name, "path": str(path), "kind": "dockerfile",
                   **result.to_dict()}
    else:
        result, err = analyze_compose(text)
        payload = {"filename": path.name, "path": str(path), "kind": "compose",
                   **result.to_dict()}
        if err:
            payload["warning"] = err
    return payload


def scan_targets(paths: list[Path], ignored: set[str]) -> list[dict]:
    """Scan all paths and filter out ignored rule ids."""
    out: list[dict] = []
    for p in paths:
        rep = scan_file(p)
        rep["findings"] = [f for f in rep.get("findings", []) if f["rule_id"] not in ignored]
        # Recompute summary
        s: dict[str, int] = {}
        for f in rep["findings"]:
            s[f["severity"]] = s.get(f["severity"], 0) + 1
        s["total"] = len(rep["findings"])
        rep["summary"] = s
        out.append(rep)
    return out


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _worst(findings: list[dict]) -> str | None:
    if not findings:
        return None
    worst = min(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
    return str(worst["severity"])


def format_text(reports: list[dict], use_color: bool = True) -> str:
    """Human-readable report for terminals."""
    B = "\033[1m" if use_color else ""
    R = "\033[0m" if use_color else ""
    CYAN = "\033[36m" if use_color else ""
    YELLOW = "\033[33m" if use_color else ""
    GREEN = "\033[32m" if use_color else ""
    GREY = "\033[90m" if use_color else ""
    lines: list[str] = []
    grand_total = 0
    for rep in reports:
        lines.append(f"\n{B}=== {rep['path']} ({rep['kind']}){R}")
        if rep.get("warning"):
            lines.append(f"  {YELLOW}! warning: {rep['warning']}{R}")
        s = rep["summary"]
        if not s.get("total"):
            lines.append(f"  {GREEN}clean{R} - no findings")
            continue
        grand_total += s["total"]
        for sev in SEVERITY_ORDER:
            n = s.get(sev, 0)
            if n:
                badge = SEVERITY_BADGE[sev] if use_color else sev.upper()
                lines.append(f"  {badge}: {n}")
        for f in rep["findings"]:
            sev = f["severity"]
            badge = SEVERITY_BADGE[sev] if use_color else sev.upper()
            where = f"line {f['line']}" if f.get("line") else "-"
            lines.append(f"\n  [{badge}] {f['rule_id']}  ({where})  {f['title']}")
            lines.append(f"    {f['description']}")
            if f.get("snippet"):
                lines.append(f"    {GREY}| {f['snippet'].splitlines()[0]}{R}")
            lines.append(f"    {CYAN}fix: {f['remediation']}{R}")
    if not reports:
        return "No files to scan."
    lines.append(f"\n{B}Grand total: {grand_total} finding(s) across {len(reports)} file(s){R}")
    return "\n".join(lines)


def format_json(reports: list[dict]) -> str:
    return json.dumps({
        "files": reports,
        "totals": _totals(reports),
    }, indent=2, ensure_ascii=False)


def format_sarif(reports: list[dict]) -> str:
    """SARIF 2.1.0 — accepted by GitHub code scanning via
    github/codeql-action/upload-sarif@v3."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for rep in reports:
        uri = "file:///" + str(Path(rep["path"]).resolve()).replace("\\", "/")
        for f in rep["findings"]:
            rid = f["rule_id"]
            if rid not in rules:
                rules[rid] = _sarif_rule(rid, f)
            results.append({
                "ruleId": rid,
                "level": _sarif_level(f["severity"]),
                "message": {"text": f"{f['title']} — {f['description']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": f["line"] or 1} if f.get("line") else {"startLine": 1},
                    }
                }],
                "properties": {
                    "severity": f["severity"],
                    "remediation": f["remediation"],
                    "snippet": f.get("snippet"),
                },
            })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Docker Hardening Checker",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/example/docker-hardening-checker",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)


def _sarif_rule(rule_id: str, sample_finding: dict) -> dict:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": sample_finding["title"]},
        "fullDescription": {"text": sample_finding["description"]},
        "help": {"text": sample_finding["remediation"]},
        "defaultConfiguration": {"level": _sarif_level(sample_finding["severity"])},
    }


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")


def format_github(reports: list[dict]) -> str:
    """Emit GitHub Actions workflow commands + a markdown step summary.

    - `::error file=...,line=... ::...` / `::warning ...` / `::notice ...` annotations
    - Appends a markdown report to $GITHUB_STEP_SUMMARY if set.
    """
    lines: list[str] = []
    summary_md: list[str] = ["# Docker Hardening Report", ""]
    totals = _totals(reports)
    summary_md.append(f"**Files scanned:** {len(reports)}  ")
    summary_md.append(f"**Total findings:** {totals.get('total', 0)}  ")
    sev_counts = " ".join(
        f"`{sev}`: {totals.get(sev, 0)}" for sev in SEVERITY_ORDER if totals.get(sev)
    )
    if sev_counts:
        summary_md.append(f"**By severity:** {sev_counts}  ")
    summary_md.append("")

    for rep in reports:
        summary_md.append(f"## `{rep['path']}` ({rep['kind']})")
        if rep.get("warning"):
            lines.append(f"::warning file={rep['path']} ::{rep['warning']}")
            summary_md.append(f"> ⚠️ {rep['warning']}")
        if not rep.get("findings"):
            summary_md.append("- ✅ clean\n")
            continue
        for f in rep["findings"]:
            sev = f["severity"]
            level = GITHUB_SEVERITY.get(sev, "warning")
            props = [f"file={rep['path']}"]
            if f.get("line"):
                props.append(f"line={f['line']}")
            if f.get("col"):
                props.append(f"col={f['col']}")
            title = f.get("title", f["rule_id"])
            msg = f"{title} ({f['rule_id']}): {f['description']}"
            lines.append(f"::{level} {','.join(props)}::{msg}")
            summary_md.append(
                f"- <sub>**[{sev.upper()}]**</sub> `{f['rule_id']}` — **{title}**"
                + (f" (line {f['line']})" if f.get("line") else "")
            )
            summary_md.append(f"  - {f['description']}")
            summary_md.append(f"  - 💡 *{f['remediation']}*")
        summary_md.append("")

    # Append to step summary if we're in GitHub Actions
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(summary_md) + "\n")
        except OSError as e:
            lines.append(f"::warning::Could not write GITHUB_STEP_SUMMARY: {e}")

    return "\n".join(lines) + "\n"


def _totals(reports: list[dict]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for rep in reports:
        for k, v in rep.get("summary", {}).items():
            totals[k] = totals.get(k, 0) + v
    return totals


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="docker-hardening-checker",
        description="Analyze Dockerfiles and docker-compose files for security bad practices.",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="Files, directories, or globs to scan. Defaults to current directory.")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, default="high",
                   help="Exit non-zero if any finding at or above this severity is present. "
                        "Default: high.")
    p.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text",
                   help="Output format. 'github' emits Actions annotations + step summary. "
                        "Default: text.")
    p.add_argument("--output", "-o", default="",
                   help="Write the report to this file instead of stdout.")
    p.add_argument("--ignore", action="append", default=[],
                   help="Rule id to ignore (can be repeated).")
    p.add_argument("--recursive", "-r", action="store_true", default=True,
                   help="When scanning directories, recurse into subdirectories. (default: on)")
    p.add_argument("--no-recursive", dest="recursive", action="store_false",
                   help="Do not recurse into subdirectories.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors in text output.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # When running inside a GitHub Actions runner with no TTY, default to the
    # github format unless the user explicitly chose something else.
    in_actions = (not args.paths or args.paths == ["."]) and os.environ.get("GITHUB_ACTIONS") == "true"
    if in_actions and args.format == "text" and not args.output:
        args.format = "github"

    targets = discover(args.paths, recursive=args.recursive)
    if not targets:
        print("No Dockerfile or docker-compose file found.", file=sys.stderr)
        return 2

    reports = scan_targets(targets, ignored=set(args.ignore))

    # Render
    use_color = (not args.no_color) and sys.stdout.isatty() and args.format == "text"
    if args.format == "text":
        rendered = format_text(reports, use_color=use_color)
    elif args.format == "json":
        rendered = format_json(reports)
    elif args.format == "sarif":
        rendered = format_sarif(reports)
    elif args.format == "github":
        rendered = format_github(reports)
    else:
        rendered = format_text(reports, use_color=use_color)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        # github format already writes the step summary separately; the rest
        # is meant for the log.
        print(rendered)

    # Decide exit code
    threshold = SEVERITY_RANK[args.fail_on]
    fail = any(
        SEVERITY_RANK.get(f["severity"], 99) <= threshold
        for rep in reports
        for f in rep["findings"]
    )
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
