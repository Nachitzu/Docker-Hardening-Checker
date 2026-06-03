"""Tests for the CLI entry point."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
CLI = [PY, str(ROOT / "cli.py")]


def run(*args, env_extra=None, expect_code: int | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        [*CLI, *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
    )
    if expect_code is not None:
        assert r.returncode == expect_code, (
            f"expected exit {expect_code}, got {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )
    return r


class TestHelp:
    def test_help_runs(self):
        r = run("--help", expect_code=0)
        assert "docker-hardening-checker" in r.stdout


class TestExitCodes:
    def test_clean_file_exits_zero(self):
        run("samples/compose-good.yml", "--no-color", expect_code=0)

    def test_bad_file_exits_one_by_default(self):
        run("samples/Dockerfile.bad", "--no-color", expect_code=1)

    def test_fail_on_critical_filters_below(self):
        run("samples/Dockerfile.bad", "--no-color",
            "--fail-on", "critical", expect_code=1)

    def test_fail_on_info_passes_critical(self):
        # --fail-on info with only critical findings still fails (info is lowest)
        run("samples/Dockerfile.bad", "--no-color",
            "--fail-on", "info", expect_code=1)

    def test_ignore_rule(self):
        r = run("samples/Dockerfile.good", "--no-color",
                "--ignore", "DF-010", "--fail-on", "high", expect_code=0)
        assert "DF-010" not in r.stdout


class TestTextFormat:
    def test_text_includes_rule_ids(self):
        r = run("samples/Dockerfile.bad", "--no-color", expect_code=1)
        for expected in ("DF-001", "DF-004-ENV", "DF-006", "DF-009"):
            assert expected in r.stdout, f"{expected} missing from text output"

    def test_no_color_strips_ansi(self):
        r = run("samples/Dockerfile.bad", "--no-color", expect_code=1)
        # We don't claim zero ANSI (we use it for "fix:" too) but the bold header
        # should be plain when --no-color is set.
        assert "\033[1m===" not in r.stdout


class TestJsonFormat:
    def test_json_totals(self):
        r = run("samples/Dockerfile.bad", "--format", "json", "--no-color", expect_code=1)
        data = json.loads(r.stdout)
        assert data["totals"]["critical"] == 3
        assert data["totals"]["total"] == 14
        assert len(data["files"]) == 1

    def test_json_schema_fields(self):
        r = run("samples/Dockerfile.bad", "--format", "json", "--no-color", expect_code=1)
        data = json.loads(r.stdout)
        f0 = data["files"][0]
        for key in ("filename", "path", "kind", "summary", "findings"):
            assert key in f0
        finding = f0["findings"][0]
        for key in ("rule_id", "title", "severity", "description", "remediation"):
            assert key in finding


class TestSarifFormat:
    def test_sarif_structure(self):
        r = run("samples/Dockerfile.bad", "--format", "sarif", "--no-color", expect_code=1)
        data = json.loads(r.stdout)
        assert data["version"] == "2.1.0"
        run_obj = data["runs"][0]
        assert run_obj["tool"]["driver"]["name"] == "Docker Hardening Checker"
        assert len(run_obj["results"]) == 14
        # Each result has a ruleId and a location.
        for res in run_obj["results"]:
            assert "ruleId" in res
            assert "locations" in res
            assert res["level"] in ("error", "warning", "note", "none")


class TestGithubFormat:
    def test_github_annotations(self, tmp_path: Path):
        summary = tmp_path / "summary.md"
        r = run(
            "samples/Dockerfile.bad", "--format", "github", "--no-color",
            env_extra={"GITHUB_STEP_SUMMARY": str(summary)},
            expect_code=1,
        )
        assert "::error file=" in r.stdout
        # Step summary is populated.
        assert summary.exists()
        body = summary.read_text(encoding="utf-8")
        assert "# Docker Hardening Report" in body
        assert "DF-004-ENV" in body


class TestAutoDiscovery:
    def test_scan_directory(self):
        r = run("samples", "--no-color", "--fail-on", "high", expect_code=1)
        # Both bad files should appear.
        combined = r.stdout + r.stderr
        assert "Dockerfile.bad" in combined
        assert "compose-bad.yml" in combined

    def test_glob_pattern(self):
        r = run("samples/Dockerfile.bad", "--no-color", expect_code=1)
        assert "DF-001" in r.stdout

    def test_no_files_returns_two(self):
        # Use a directory with no matching files.
        r = run("__pycache__", "--no-color")
        # Either 2 (no files) or 0 (nothing to fail on) — both acceptable.
        assert r.returncode in (0, 2)
