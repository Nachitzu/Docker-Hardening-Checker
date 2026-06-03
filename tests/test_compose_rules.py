"""Tests for docker-compose analysis rules."""
from __future__ import annotations

import pytest

from app import _published_ports, analyze_compose

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rules(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def _find(result, rule_id_prefix: str) -> bool:
    return any(f.rule_id.startswith(rule_id_prefix) for f in result.findings)


# ---------------------------------------------------------------------------
# YAML parse errors
# ---------------------------------------------------------------------------

class TestParseErrors:
    def test_invalid_yaml_returns_warning(self):
        _result, err = analyze_compose("services:\n  api:\n   image: 'unterminated")
        assert err is not None
        assert "YAML" in err

    def test_empty_yaml(self):
        _result, err = analyze_compose("")
        assert err == "Empty YAML document"


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

class TestStructure:
    def test_no_services_key(self):
        result, _ = analyze_compose("foo: bar\n")
        assert any(f.rule_id == "DC-000" for f in result.findings)

    def test_empty_services(self):
        result, _ = analyze_compose("services: {}\n")
        assert any(f.rule_id == "DC-EMPTY" for f in result.findings)

    def test_legacy_v2(self):
        result, _ = analyze_compose("version: '2.4'\nservices:\n  api:\n    image: nginx:1.27\n")
        assert any(f.rule_id == "DC-VER" for f in result.findings)


# ---------------------------------------------------------------------------
# Image pinning
# ---------------------------------------------------------------------------

class TestImagePinning:
    def test_unpinned_image(self):
        text = "services:\n  api:\n    image: myapi\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-002") for f in result.findings)

    def test_latest_image(self):
        text = "services:\n  api:\n    image: myapi:latest\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-002") for f in result.findings)

    def test_pinned_image_ok(self):
        text = "services:\n  api:\n    image: nginx:1.27.3\n"
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-002") for f in result.findings)

    def test_no_image_no_build(self):
        text = "services:\n  api:\n    command: ['echo', 'hi']\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id == "DC-001" for f in result.findings)


# ---------------------------------------------------------------------------
# Privilege / capabilities
# ---------------------------------------------------------------------------

class TestPrivilege:
    def test_privileged(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    privileged: true\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-003") for f in result.findings)

    @pytest.mark.parametrize("cap", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE",
                                     "ALL", "NET_RAW"])
    def test_dangerous_cap(self, cap):
        text = f"services:\n  api:\n    image: nginx:1.27\n    cap_add: [{cap}]\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-004") for f in result.findings), \
            f"cap {cap} should trigger DC-004"

    def test_no_cap_drop_baseline(self):
        text = "services:\n  api:\n    image: nginx:1.27\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-005") for f in result.findings)

    def test_cap_drop_present_ok(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    cap_drop: [ALL]\n"
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-005") for f in result.findings)


# ---------------------------------------------------------------------------
# Namespace sharing
# ---------------------------------------------------------------------------

class TestNamespaces:
    def test_network_host(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    network_mode: host\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-006") for f in result.findings)

    def test_pid_host(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    pid: host\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-007") for f in result.findings)

    def test_ipc_host(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    ipc: host\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-008") for f in result.findings)


# ---------------------------------------------------------------------------
# user
# ---------------------------------------------------------------------------

class TestUser:
    def test_no_user_flagged(self):
        text = "services:\n  api:\n    image: nginx:1.27\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-009") for f in result.findings)

    def test_explicit_root_flagged(self):
        text = 'services:\n  api:\n    image: nginx:1.27\n    user: "0"\n'
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-010") for f in result.findings)

    def test_unprivileged_ok(self):
        text = 'services:\n  api:\n    image: nginx:1.27\n    user: "1000:1000"\n'
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-009") for f in result.findings)
        assert not any(f.rule_id.startswith("DC-010") for f in result.findings)


# ---------------------------------------------------------------------------
# read_only
# ---------------------------------------------------------------------------

class TestReadOnly:
    def test_read_only_missing(self):
        text = "services:\n  api:\n    image: nginx:1.27\n"
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-011") for f in result.findings)

    def test_read_only_present(self):
        text = "services:\n  api:\n    image: nginx:1.27\n    read_only: true\n"
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-011") for f in result.findings)


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

class TestSecrets:
    def test_secret_in_environment_dict(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    environment:\n"
            "      DB_PASSWORD: hunter2\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-012") for f in result.findings)

    def test_secret_in_environment_list(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    environment:\n"
            "      - DB_PASSWORD=hunter2\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-012") for f in result.findings)

    def test_environment_placeholder_ok(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    environment:\n"
            "      DB_PASSWORD: ${DB_PASSWORD}\n"
        )
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-012") for f in result.findings)

    def test_env_file_dotenv_flagged(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    env_file:\n"
            "      - .env\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-013") for f in result.findings)

    def test_secrets_block_inline(self):
        text = (
            "secrets:\n  db_pw:\n    file: ./db_pw.txt\n"
            "services:\n  api:\n    image: nginx:1.27\n    secrets:\n"
            "      - db_pw\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-SECRET") for f in result.findings)


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

class TestPorts:
    @pytest.mark.parametrize("port", [22, 3306, 5432, 6379, 3389])
    def test_sensitive_port_on_all_interfaces(self, port):
        text = (
            f"services:\n  api:\n    image: nginx:1.27\n    ports:\n"
            f"      - 0.0.0.0:{port}:{port}\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-014") for f in result.findings)

    def test_sensitive_port_on_loopback_ok(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    ports:\n"
            "      - 127.0.0.1:3306:3306\n"
        )
        result, _ = analyze_compose(text)
        assert not any(f.rule_id.startswith("DC-014") for f in result.findings)


# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------

class TestVolumes:
    @pytest.mark.parametrize("path", ["/", "/etc", "/proc", "/sys", "/dev"])
    def test_sensitive_host_path(self, path):
        text = (
            f"services:\n  api:\n    image: nginx:1.27\n    volumes:\n"
            f"      - {path}:/mnt\n"
        )
        result, _ = analyze_compose(text)
        assert any(f.rule_id.startswith("DC-015") for f in result.findings), \
            f"path {path} should trigger DC-015"

    def test_docker_socket(self):
        text = (
            "services:\n  api:\n    image: nginx:1.27\n    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        result, _ = analyze_compose(text)
        # Should trigger both DC-015 (sensitive path) and DC-016 (docker socket).
        rules = _rules(result)
        assert any(r.startswith("DC-015") for r in rules)
        assert any(r.startswith("DC-016") for r in rules)


# ---------------------------------------------------------------------------
# _published_ports parser helper
# ---------------------------------------------------------------------------

class TestPublishedPorts:
    def test_short_form(self):
        out = _published_ports(["8080"])
        assert out == [{"published": 8080, "target": 8080, "host_ip": "0.0.0.0", "protocol": "tcp"}]

    def test_long_form(self):
        out = _published_ports(["8080:80"])
        assert out[0]["published"] == 8080
        assert out[0]["target"] == 80

    def test_with_host_ip(self):
        out = _published_ports(["127.0.0.1:8080:80"])
        assert out[0]["host_ip"] == "127.0.0.1"

    def test_with_protocol(self):
        out = _published_ports(["8080:80/udp"])
        assert out[0]["protocol"] == "udp"

    def test_dict_form(self):
        out = _published_ports([{"published": 8080, "target": 80, "host_ip": "127.0.0.1"}])
        assert out[0]["host_ip"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# End-to-end on bundled samples
# ---------------------------------------------------------------------------

class TestSampleIntegration:
    def test_bad_sample_flags_expected_rules(self, bad_compose):
        result, err = analyze_compose(bad_compose)
        assert err is None
        rules = _rules(result)
        # All of these should fire on compose-bad.yml.
        for prefix in ("DC-002", "DC-003", "DC-004", "DC-006", "DC-007", "DC-009",
                       "DC-011", "DC-012", "DC-013", "DC-014", "DC-015", "DC-016"):
            assert any(r.startswith(prefix) for r in rules), f"{prefix} missing"

    def test_good_sample_clean(self, good_compose):
        result, err = analyze_compose(good_compose)
        assert err is None
        # The good sample is genuinely clean.
        assert result.findings == []
