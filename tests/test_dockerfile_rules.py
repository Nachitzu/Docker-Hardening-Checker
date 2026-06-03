"""Tests for Dockerfile analysis rules."""
from __future__ import annotations

import pytest

from app import (
    Finding,
    analyze_dockerfile,
    is_pinned,
    parse_dockerfile,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rules(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def _find(result, rule_id: str) -> Finding | None:
    for f in result.findings:
        if f.rule_id == rule_id:
            return f
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestParseDockerfile:
    def test_basic_from(self):
        ins = parse_dockerfile("FROM ubuntu:22.04")
        assert len(ins) == 1
        assert ins[0].cmd == "FROM"
        assert ins[0].value == "ubuntu:22.04"
        assert ins[0].line == 1

    def test_line_continuation(self):
        text = "RUN apt-get update \\\n    && apt-get install -y foo"
        ins = parse_dockerfile(text)
        assert len(ins) == 1
        assert ins[0].cmd == "RUN"
        assert "apt-get update" in ins[0].value
        assert "apt-get install" in ins[0].value
        assert ins[0].is_continuation is True

    def test_comment_skipped(self):
        text = "# this is a comment\nFROM alpine:3.19"
        ins = parse_dockerfile(text)
        assert len(ins) == 1
        assert ins[0].cmd == "FROM"

    def test_multi_stage(self):
        text = "FROM golang:1.22 AS builder\nFROM alpine:3.19"
        ins = parse_dockerfile(text)
        assert len(ins) == 2
        assert "builder" in ins[0].value


class TestIsPinned:
    @pytest.mark.parametrize("image,expected_pinned,reason_match", [
        ("nginx", False, "no tag"),
        ("nginx:latest", False, "latest"),
        ("nginx:1.27.3", True, "1.27.3"),
        ("nginx:1.27.3@sha256:abc", True, "digest"),
        ("registry.io/foo/bar:1.0", True, "1.0"),
    ])
    def test_pinning(self, image, expected_pinned, reason_match):
        pinned, reason = is_pinned(image)
        assert pinned is expected_pinned
        assert reason_match.lower() in reason.lower()


# ---------------------------------------------------------------------------
# Empty / minimal
# ---------------------------------------------------------------------------

class TestEmptyDockerfile:
    def test_completely_empty(self):
        r = analyze_dockerfile("")
        assert r.target == "Dockerfile"
        assert any(f.rule_id == "DF-EMPTY" for f in r.findings)

    def test_only_comments(self):
        r = analyze_dockerfile("# nothing here\n# still nothing\n")
        assert any(f.rule_id == "DF-EMPTY" for f in r.findings)


# ---------------------------------------------------------------------------
# DF-001 / DF-001b — image pinning
# ---------------------------------------------------------------------------

class TestImagePinning:
    def test_unpinned_no_tag(self):
        r = analyze_dockerfile("FROM ubuntu\nCMD [\"sh\"]")
        assert _find(r, "DF-001") is not None
        assert _find(r, "DF-001b") is not None

    def test_latest_tag(self):
        r = analyze_dockerfile("FROM node:latest\nCMD [\"node\"]")
        # DF-001 catches :latest; DF-001b is for no tag at all.
        assert _find(r, "DF-001") is not None
        assert _find(r, "DF-001b") is None

    def test_pinned_specific_tag(self):
        r = analyze_dockerfile("FROM python:3.12-slim\nCMD [\"python\"]")
        assert _find(r, "DF-001") is None
        assert _find(r, "DF-001b") is None

    def test_pinned_by_digest(self):
        r = analyze_dockerfile("FROM python:3.12-slim@sha256:abc123\nCMD [\"python\"]")
        assert _find(r, "DF-001") is None


# ---------------------------------------------------------------------------
# DF-002 / DF-002b / DF-003 — USER
# ---------------------------------------------------------------------------

class TestUserDirective:
    def test_no_user_is_critical(self):
        r = analyze_dockerfile("FROM alpine:3.19\nCMD [\"sh\"]")
        f = _find(r, "DF-002")
        assert f is not None
        assert f.severity == "critical"

    def test_user_root_is_critical(self):
        r = analyze_dockerfile("FROM alpine:3.19\nUSER root\nCMD [\"sh\"]")
        assert _find(r, "DF-002b") is not None
        # DF-002 only fires when USER is missing; with USER root present it shouldn't.
        assert _find(r, "DF-002") is None

    def test_user_zero_is_critical(self):
        r = analyze_dockerfile("FROM alpine:3.19\nUSER 0\nCMD [\"sh\"]")
        assert _find(r, "DF-002b") is not None

    def test_unprivileged_user_ok(self):
        r = analyze_dockerfile("FROM alpine:3.19\nRUN adduser -D app\nUSER app\nCMD [\"./run\"]")
        assert _find(r, "DF-002") is None
        assert _find(r, "DF-002b") is None

    def test_run_after_user_is_flagged(self):
        r = analyze_dockerfile("FROM alpine:3.19\nUSER app\nRUN echo hi > /tmp/x")
        assert _find(r, "DF-003") is not None


# ---------------------------------------------------------------------------
# DF-004 — secrets in ENV / ARG
# ---------------------------------------------------------------------------

class TestSecretsInEnvArg:
    def test_env_password_detected(self):
        r = analyze_dockerfile("FROM alpine\nENV DB_PASSWORD=hunter2\nCMD [\"sh\"]")
        assert _find(r, "DF-004-ENV") is not None

    def test_env_aws_key_detected(self):
        r = analyze_dockerfile("FROM alpine\nENV AWS_SECRET_ACCESS_KEY=AKIAEXAMPLE\nCMD [\"sh\"]")
        assert _find(r, "DF-004-ENV") is not None

    def test_arg_token_detected(self):
        r = analyze_dockerfile("FROM alpine\nARG API_TOKEN=abc123\nCMD [\"sh\"]")
        assert _find(r, "DF-004-ARG") is not None

    def test_env_placeholder_not_flagged(self):
        r = analyze_dockerfile("FROM alpine\nENV DB_PASSWORD=${DB_PASSWORD}\nCMD [\"sh\"]")
        assert _find(r, "DF-004-ENV") is None

    def test_env_innocuous_not_flagged(self):
        r = analyze_dockerfile("FROM alpine\nENV LOG_LEVEL=info\nCMD [\"sh\"]")
        assert _find(r, "DF-004-ENV") is None


# ---------------------------------------------------------------------------
# DF-005 — ADD for local files
# ---------------------------------------------------------------------------

class TestAdd:
    def test_add_local_flagged(self):
        r = analyze_dockerfile("FROM alpine\nADD app.py /app/app.py\nCMD [\"sh\"]")
        assert _find(r, "DF-005") is not None

    def test_add_url_not_flagged(self):
        r = analyze_dockerfile("FROM alpine\nADD https://example.com/foo.tar /tmp/foo\nCMD [\"sh\"]")
        assert _find(r, "DF-005") is None

    def test_add_tar_not_flagged(self):
        r = analyze_dockerfile("FROM alpine\nADD archive.tar.gz /tmp\nCMD [\"sh\"]")
        assert _find(r, "DF-005") is None


# ---------------------------------------------------------------------------
# DF-006 — curl | sh
# ---------------------------------------------------------------------------

class TestPipeToShell:
    def test_curl_pipe_sh(self):
        r = analyze_dockerfile("FROM alpine\nRUN curl -sSL https://example.com/install.sh | sh\nCMD [\"sh\"]")
        assert _find(r, "DF-006") is not None

    def test_wget_pipe_bash(self):
        r = analyze_dockerfile("FROM alpine\nRUN wget -qO- https://example.com/install.sh | bash\nCMD [\"sh\"]")
        assert _find(r, "DF-006") is not None

    def test_safe_curl_not_flagged(self):
        r = analyze_dockerfile("FROM alpine\nRUN curl -fSL https://example.com/file.tar.gz -o /tmp/f.tar\nCMD [\"sh\"]")
        assert _find(r, "DF-006") is None


# ---------------------------------------------------------------------------
# DF-007 / DF-007b — apt-get hygiene
# ---------------------------------------------------------------------------

class TestAptGetHygiene:
    def test_no_no_install_recommends(self):
        r = analyze_dockerfile("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\nCMD [\"sh\"]")
        assert _find(r, "DF-007") is not None

    def test_no_cache_cleanup(self):
        r = analyze_dockerfile("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\nCMD [\"sh\"]")
        assert _find(r, "DF-007b") is not None

    def test_clean_apt(self):
        r = analyze_dockerfile(
            "FROM ubuntu:22.04\n"
            "RUN apt-get update && apt-get install --no-install-recommends -y curl "
            "&& rm -rf /var/lib/apt/lists/*\n"
            "CMD [\"sh\"]"
        )
        assert _find(r, "DF-007") is None
        assert _find(r, "DF-007b") is None


# ---------------------------------------------------------------------------
# DF-008 — HEALTHCHECK
# ---------------------------------------------------------------------------

class TestHealthcheck:
    def test_no_healthcheck_with_cmd(self):
        r = analyze_dockerfile("FROM alpine\nCMD [\"sh\"]")
        assert _find(r, "DF-008") is not None

    def test_healthcheck_present(self):
        r = analyze_dockerfile("FROM alpine\nHEALTHCHECK CMD true\nCMD [\"sh\"]")
        assert _find(r, "DF-008") is None


# ---------------------------------------------------------------------------
# DF-009 — sensitive ports
# ---------------------------------------------------------------------------

class TestExposedPorts:
    @pytest.mark.parametrize("port", [22, 23, 25, 3389, 3306, 5432, 6379])
    def test_sensitive_port(self, port):
        r = analyze_dockerfile(f"FROM alpine\nEXPOSE {port}\nCMD [\"sh\"]")
        assert _find(r, "DF-009") is not None

    def test_innocuous_port_ok(self):
        r = analyze_dockerfile("FROM alpine\nEXPOSE 8080\nCMD [\"sh\"]")
        assert _find(r, "DF-009") is None


# ---------------------------------------------------------------------------
# DF-010 — COPY . .
# ---------------------------------------------------------------------------

class TestCopyAll:
    def test_copy_dot_dot_flagged(self):
        r = analyze_dockerfile("FROM alpine\nCOPY . .\nCMD [\"sh\"]")
        assert _find(r, "DF-010") is not None

    def test_targeted_copy_ok(self):
        r = analyze_dockerfile("FROM alpine\nCOPY app.py /app/app.py\nCMD [\"sh\"]")
        assert _find(r, "DF-010") is None


# ---------------------------------------------------------------------------
# DF-011 — WORKDIR absolute
# ---------------------------------------------------------------------------

class TestWorkdir:
    def test_relative_workdir(self):
        r = analyze_dockerfile("FROM alpine\nWORKDIR app\nCMD [\"sh\"]")
        assert _find(r, "DF-011") is not None

    def test_absolute_workdir_ok(self):
        r = analyze_dockerfile("FROM alpine\nWORKDIR /app\nCMD [\"sh\"]")
        assert _find(r, "DF-011") is None


# ---------------------------------------------------------------------------
# End-to-end on bundled samples
# ---------------------------------------------------------------------------

class TestSampleIntegration:
    def test_bad_sample_finds_almost_everything(self, bad_dockerfile):
        r = analyze_dockerfile(bad_dockerfile)
        # All of these rules should fire on the bad sample.
        for rule in ("DF-001", "DF-001b", "DF-003", "DF-004-ENV", "DF-004-ARG",
                     "DF-006", "DF-007", "DF-007b", "DF-008", "DF-009", "DF-010", "DF-011"):
            assert _find(r, rule) is not None, f"rule {rule} should fire on Dockerfile.bad"

    def test_good_sample_clean(self, good_dockerfile):
        r = analyze_dockerfile(good_dockerfile)
        # No critical or high findings in the good sample.
        for f in r.findings:
            assert f.severity in ("low", "info", "medium"), \
                f"unexpected severity {f.severity} for {f.rule_id} in Dockerfile.good"
