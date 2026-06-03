"""
Docker Hardening Checker
Web UI that analyzes Dockerfiles and docker-compose.yml files for security bad practices.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB upload cap


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    description: str
    remediation: str
    line: int | None = None
    snippet: str | None = None
    rule_url: str | None = None


@dataclass
class AnalysisResult:
    target: str  # "Dockerfile" or "docker-compose"
    summary: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "summary": self.summary,
            "findings": [asdict(f) for f in sorted(
                self.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.line or 0)
            )],
        }


# ---------------------------------------------------------------------------
# Dockerfile parsing (line-based, since Dockerfile grammar is line-oriented)
# ---------------------------------------------------------------------------

DOCKERFILE_DIRECTIVE = re.compile(r"^\s*([A-Z]+)\s+(.*)$")
# Match "password", "secret", etc. as substrings; boundaries use \W so that
# identifiers like `DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY` still hit.
SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])("
    r"password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|db[_-]?pass|mysql[_-]?root[_-]?password"
    r")(?:$|[^A-Za-z0-9])"
)
SENSITIVE_PORTS = {22, 23, 25, 3389, 5432, 3306, 6379, 9200, 27017}


@dataclass
class DockerInstruction:
    cmd: str
    value: str
    line: int
    raw: str
    is_continuation: bool = False


def parse_dockerfile(text: str) -> list[DockerInstruction]:
    """Tokenize a Dockerfile honoring line continuations and comments."""
    out: list[DockerInstruction] = []
    current: DockerInstruction | None = None
    for idx, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            # Continuation of the previous instruction (e.g. blank line as terminator).
            if current is not None and not stripped:
                out.append(current)
                current = None
            continue
        # Line continuation: trailing backslash
        if raw.rstrip().endswith("\\"):
            piece = raw.rstrip()[:-1].rstrip()
            if current is None:
                cmd, _, value = piece.partition(" ")
                current = DockerInstruction(
                    cmd=cmd.upper(),
                    value=value,
                    line=idx,
                    raw=raw,
                    is_continuation=False,
                )
            else:
                current.value = (current.value + " " + piece.strip()).strip()
                current.raw += "\n" + raw
                current.is_continuation = True
            continue
        # Otherwise it's a fresh instruction (or terminates the current one).
        if current is not None:
            out.append(current)
            current = None
        m = DOCKERFILE_DIRECTIVE.match(stripped)
        if m:
            out.append(DockerInstruction(cmd=m.group(1).upper(), value=m.group(2).strip(),
                                         line=idx, raw=raw))
        else:
            # Continuation line without leading directive — attach to previous.
            if out:
                out[-1].value = (out[-1].value + " " + stripped).strip()
                out[-1].raw += "\n" + raw
                out[-1].is_continuation = True
    if current is not None:
        out.append(current)
    return out


def is_pinned(image_ref: str) -> tuple[bool, str]:
    """Return (is_pinned, reason). Image ref like 'nginx' or 'nginx:1.25' or 'nginx@sha256:...'."""
    if "@sha256:" in image_ref:
        return True, "pinned by digest"
    if ":" not in image_ref.split("/")[-1]:
        return False, "no tag (resolves to :latest)"
    tag = image_ref.rsplit(":", 1)[1].split("@")[0]
    if tag.lower() == "latest":
        return False, "tag is :latest"
    return True, f"pinned to :{tag}"


# ---------------------------------------------------------------------------
# Dockerfile rules
# ---------------------------------------------------------------------------

def analyze_dockerfile(text: str) -> AnalysisResult:
    result = AnalysisResult(target="Dockerfile")
    instructions = parse_dockerfile(text)
    if not instructions:
        result.findings.append(Finding(
            rule_id="DF-EMPTY",
            title="Dockerfile is empty",
            severity="high",
            description="No instructions were found in the file.",
            remediation="Add at least a FROM instruction.",
        ))
        return result

    has_user = False
    has_user_root = False
    for ins in instructions:
        if ins.cmd == "USER":
            has_user = True
            if ins.value.strip().lower() in {"root", "0"}:
                has_user_root = True
    from_refs = [ins for ins in instructions if ins.cmd == "FROM"]
    run_refs = [ins for ins in instructions if ins.cmd == "RUN"]

    # --- FROM / image pinning ---
    for ins in from_refs:
        # Handle multi-stage: 'FROM image AS stage'
        first_token = ins.value.split()[0]
        pinned, reason = is_pinned(first_token)
        if not pinned:
            result.findings.append(Finding(
                rule_id="DF-001",
                title=f"Unpinned base image: {first_token}",
                severity="high",
                description=f"Image '{first_token}' is {reason}. Unpinned images break reproducibility and "
                           "can pull breaking or malicious updates on rebuild.",
                remediation="Pin to a specific version (`nginx:1.27.3`) or, better, a digest "
                            "(`nginx:1.27.3@sha256:...`).",
                line=ins.line,
                snippet=ins.raw.strip(),
                rule_url="https://docs.docker.com/engine/reference/builder/#from",
            ))
        # AS alias in multi-stage can hide which stage is the final one; flag suspicious base images
        if ":" not in first_token.split("/")[-1]:
            result.findings.append(Finding(
                rule_id="DF-001b",
                title="Base image without tag",
                severity="high",
                description="When no tag is specified, Docker defaults to :latest, which makes builds "
                            "non-reproducible.",
                remediation="Add an explicit tag, e.g. `FROM python:3.12-slim`.",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))

    # --- USER directive ---
    if not has_user:
        result.findings.append(Finding(
            rule_id="DF-002",
            title="Container runs as root (no USER directive)",
            severity="critical",
            description="If no USER directive is set, the container runs as root by default. A successful "
                        "exploit inside the container would then have root privileges inside it, and any "
                        "volume mount or kernel capability would be maximally exposed.",
            remediation="Create a dedicated unprivileged user (`RUN adduser --system --no-create-home app`) "
                        "and switch with `USER app` before the ENTRYPOINT/CMD.",
            line=instructions[-1].line,
            rule_url="https://docs.docker.com/engine/reference/builder/#user",
        ))
    elif has_user_root:
        result.findings.append(Finding(
            rule_id="DF-002b",
            title="USER explicitly set to root",
            severity="critical",
            description="`USER root` defeats the purpose of least privilege.",
            remediation="Remove the USER root directive or switch to a dedicated non-root user.",
        ))

    # --- USER must come after package installs ---
    user_idx = next((i for i, ins in enumerate(instructions) if ins.cmd == "USER"), None)
    last_run_after_user = any(
        ins.cmd == "RUN"
        and user_idx is not None
        and idx > user_idx
        for idx, ins in enumerate(instructions)
    )
    if user_idx is not None and last_run_after_user:
        result.findings.append(Finding(
            rule_id="DF-003",
            title="RUN after USER directive",
            severity="high",
            description="There is a RUN instruction after USER. Anything installed there will be owned by "
                        "the unprivileged user, which often causes 'permission denied' errors and pushes teams "
                        "to set USER back to root. Reorder: install as root, then USER.",
            remediation="Move the final USER directive to the end of the Dockerfile, after all RUN/COPY/ADD.",
        ))

    # --- Secrets in ENV / ARG ---
    for ins in instructions:
        if ins.cmd in {"ENV", "ARG"}:
            # `ENV KEY=value` or `ARG KEY=value` or `ARG KEY=default`
            for pair in re.split(r"\s+", ins.value):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if SECRET_KEY_RE.search(k) and v and v.strip():
                    # Heuristic: only flag if value looks like a real secret
                    is_placeholder = re.fullmatch(
                        r"(?i)(\$\{?[A-Z0-9_]+\}?|<[^>]+>|\".*\"|'.*'|changeit|example|placeholder|xxx+)",
                        v.strip(),
                    )
                    if is_placeholder:
                        continue
                    result.findings.append(Finding(
                        rule_id=f"DF-004-{'ENV' if ins.cmd == 'ENV' else 'ARG'}",
                        title=f"Possible secret in {ins.cmd}: {k}",
                        severity="critical",
                        description=f"`{ins.cmd} {k}=...` looks like a hard-coded secret. ENV values are "
                                    "visible in `docker inspect` and image layers; ARG values are visible in "
                                    "build history.",
                        remediation="Inject secrets at runtime (`docker run -e`, Docker secrets, or a vault) "
                                    "or use BuildKit's `--secret` mount for build-time values.",
                        line=ins.line,
                        snippet=ins.raw.strip(),
                    ))

    # --- ENV without value (uninitialized variable) is a smell, not a vuln ---
    for ins in instructions:
        if ins.cmd == "ENV":
            for pair in re.split(r"\s+", ins.value):
                if "=" not in pair and pair:
                    # Bare `ENV KEY` is fine; the value is taken from the environment
                    continue

    # --- ADD used to copy local files ---
    for ins in instructions:
        if ins.cmd == "ADD":
            # ADD takes "src dst" or "src... dst" (with multiple sources). Only
            # check the FIRST source token — the destination is always last and
            # is a path inside the image, not a URL or archive.
            first_src = ins.value.split()[0].lower()
            looks_like_url = first_src.startswith("http://") or first_src.startswith("https://")
            looks_like_archive = (
                first_src.endswith(".tar") or first_src.endswith(".tar.gz")
                or first_src.endswith(".tgz") or first_src.endswith(".zip")
            )
            if not (looks_like_url or looks_like_archive):
                result.findings.append(Finding(
                    rule_id="DF-005",
                    title="ADD used for local files",
                    severity="low",
                    description="ADD has extra magic (URL fetch, tar auto-extract) that you almost never want. "
                                "Using ADD for plain local copies is a code smell and a potential confusion vector.",
                    remediation="Replace with COPY unless you specifically need ADD's tar/URL features.",
                    line=ins.line,
                    snippet=ins.raw.strip(),
                ))

    # --- curl | sh, wget | sh ---
    for ins in run_refs:
        v = ins.value
        if re.search(r"(curl|wget)\s+[^|]*\|\s*(sh|bash|sudo\s+sh|sudo\s+bash)", v, re.IGNORECASE):
            result.findings.append(Finding(
                rule_id="DF-006",
                title="Piping a remote download into a shell",
                severity="high",
                description="`curl ... | sh` is dangerous: the remote script can change at any time, MITM can "
                            "swap the payload, and the build is not reproducible. There's also no signature check.",
                remediation="Download to a file, verify its checksum or signature, then run.",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))

    # --- apt-get without --no-install-recommends ---
    for ins in run_refs:
        v = ins.value
        if "apt-get install" in v and "--no-install-recommends" not in v:
            result.findings.append(Finding(
                rule_id="DF-007",
                title="apt-get install without --no-install-recommends",
                severity="low",
                description="Recommended packages bloat the image and pull in extra services that increase "
                            "the attack surface.",
                remediation="Use `apt-get install --no-install-recommends` and clean the apt cache in the same "
                            "RUN (`rm -rf /var/lib/apt/lists/*`).",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))
        if "apt-get install" in v and "rm -rf /var/lib/apt/lists" not in v and "apt-get clean" not in v:
            result.findings.append(Finding(
                rule_id="DF-007b",
                title="apt cache not cleaned in the same RUN",
                severity="low",
                description="Leaving /var/lib/apt/lists in the image leaks package metadata and bloats layers.",
                remediation="Append `&& rm -rf /var/lib/apt/lists/*` to the same RUN.",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))

    # --- HEALTHCHECK missing ---
    has_health = any(i.cmd == "HEALTHCHECK" for i in instructions)
    has_cmd = any(i.cmd in {"CMD", "ENTRYPOINT"} for i in instructions)
    if not has_health and has_cmd:
        result.findings.append(Finding(
            rule_id="DF-008",
            title="No HEALTHCHECK defined",
            severity="low",
            description="Without HEALTHCHECK the orchestrator cannot tell a healthy process from a hung one.",
            remediation="Add a HEALTHCHECK instruction, e.g. `HEALTHCHECK CMD curl -f http://localhost/ || exit 1`.",
        ))

    # --- EXPOSE of sensitive ports ---
    for ins in instructions:
        if ins.cmd == "EXPOSE":
            for token in re.split(r"\s+", ins.value.strip()):
                port_str = token.split("/")[0]
                if not port_str.isdigit():
                    continue
                port = int(port_str)
                if port in SENSITIVE_PORTS:
                    result.findings.append(Finding(
                        rule_id="DF-009",
                        title=f"Sensitive port EXPOSEd: {port}",
                        severity="high",
                        description=f"Port {port} is a well-known management port (SSH, RDP, Postgres, etc.). "
                                    "Exposing it inside an image is a strong smell — the application should not "
                                    "expose management interfaces at all.",
                        remediation="Remove this EXPOSE. If the service must be reachable, restrict it to a "
                                    "private network in docker-compose and never publish to 0.0.0.0.",
                        line=ins.line,
                        snippet=ins.raw.strip(),
                    ))

    # --- COPY/ADD entire working dir into root ---
    for ins in instructions:
        if ins.cmd in {"COPY", "ADD"} and ins.value.strip().rstrip().endswith(" ."):
            result.findings.append(Finding(
                rule_id="DF-010",
                title="COPY . . copies the whole build context",
                severity="medium",
                description="`COPY . .` ships the build context into the image, including .git, .env, node_modules, "
                            "and any other file present on the host. Secrets checked in by accident will be baked in.",
                remediation="Use a .dockerignore file to exclude sensitive/unnecessary paths, and copy only what "
                            "you need.",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))

    # --- WORKDIR not absolute ---
    for ins in instructions:
        if ins.cmd == "WORKDIR" and not ins.value.startswith("/"):
            result.findings.append(Finding(
                rule_id="DF-011",
                title="WORKDIR is not absolute",
                severity="low",
                description="Relative WORKDIR paths depend on whatever the base image set as cwd, which is "
                            "fragile and confusing.",
                remediation="Use an absolute path, e.g. `WORKDIR /app`.",
                line=ins.line,
                snippet=ins.raw.strip(),
            ))

    # --- Default ENV PATH issues (less common, skipped) ---
    # Summary
    for f in result.findings:
        result.summary[f.severity] = result.summary.get(f.severity, 0) + 1
    result.summary["total"] = len(result.findings)
    return result


# ---------------------------------------------------------------------------
# docker-compose rules
# ---------------------------------------------------------------------------

DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH",
    "ALL", "NET_RAW", "SYS_RAWIO", "MKNOD", "SYSLOG", "AUDIT_WRITE",
}
SENSITIVE_VOLUME_PATHS = [
    "/", "/etc", "/proc", "/sys", "/var/run/docker.sock", "/dev",
    "/root/.ssh", "/home",
]
SECRET_ENV_KEY_RE = SECRET_KEY_RE  # reuse
SENSITIVE_HOST_PORTS = SENSITIVE_PORTS


def _walk_services(data: Any) -> list[tuple[str, dict]]:
    services = []
    if isinstance(data, dict) and "services" in data and isinstance(data["services"], dict):
        for name, body in data["services"].items():
            if isinstance(body, dict):
                services.append((str(name), body))
    return services


def _published_ports(ports_field: Any) -> list[dict]:
    """Normalize the 'ports' field into [{published, target, host_ip, protocol}, ...]."""
    out: list[dict] = []
    if ports_field is None:
        return out
    if isinstance(ports_field, list):
        for entry in ports_field:
            if isinstance(entry, str):
                # forms: "8080", "8080:80", "127.0.0.1:8080:80", "8080:80/tcp"
                proto = "tcp"
                e = entry
                if "/" in e:
                    e, proto = e.rsplit("/", 1)
                parts = e.split(":")
                if len(parts) == 1:
                    out.append({"published": int(parts[0]), "target": int(parts[0]),
                                "host_ip": "0.0.0.0", "protocol": proto})
                elif len(parts) == 2:
                    out.append({"published": int(parts[0]), "target": int(parts[1]),
                                "host_ip": "0.0.0.0", "protocol": proto})
                elif len(parts) == 3:
                    out.append({"published": int(parts[1]), "target": int(parts[2]),
                                "host_ip": parts[0], "protocol": proto})
            elif isinstance(entry, dict):
                out.append({
                    "published": entry.get("published", entry.get("target")),
                    "target": entry.get("target", entry.get("published")),
                    "host_ip": entry.get("host_ip", "0.0.0.0"),
                    "protocol": entry.get("protocol", "tcp"),
                })
    return out


def analyze_compose(text: str) -> tuple[AnalysisResult, str | None]:
    result = AnalysisResult(target="docker-compose.yml")
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return result, f"YAML parse error: {e}"
    if loaded is None:
        return result, "Empty YAML document"

    if not isinstance(loaded, dict) or "services" not in loaded:
        result.findings.append(Finding(
            rule_id="DC-000",
            title="No top-level 'services' key",
            severity="high",
            description="This file does not look like a docker-compose document. Expected a 'services:' map "
                        "at the top level.",
            remediation="Make sure the file is a compose file (v2/v3) and starts with a `services:` key.",
        ))
        return result, None

    # Top-level checks
    if isinstance(loaded.get("version"), str) and loaded["version"].startswith("2."):
        result.findings.append(Finding(
            rule_id="DC-VER",
            title="Compose file uses legacy version '2.x'",
            severity="info",
            description="Compose v2 (the binary) ignores the 'version' key, and the v2 file format is legacy. "
                        "Modern compose specs (no version key) are recommended.",
            remediation="Drop the version key and rely on the current compose-spec.",
        ))

    services = _walk_services(loaded)
    if not services:
        result.findings.append(Finding(
            rule_id="DC-EMPTY",
            title="No services defined",
            severity="high",
            description="The services map is empty.",
            remediation="Add at least one service.",
        ))
        return result, None

    for name, svc in services:
        prefix = f"[{name}] "

        # --- Image pinning ---
        image = svc.get("image")
        build = svc.get("build")
        if image is None and build is None:
            result.findings.append(Finding(
                rule_id="DC-001",
                title=f"{prefix}No 'image' or 'build'",
                severity="high",
                description="A service must declare how to obtain its image.",
                remediation="Add either `image: name:tag` or a `build:` section.",
            ))
        elif isinstance(image, str):
            pinned, reason = is_pinned(image)
            if not pinned:
                result.findings.append(Finding(
                    rule_id=f"DC-002-{name}",
                    title=f"{prefix}Unpinned image: {image}",
                    severity="high",
                    description=f"Image '{image}' is {reason}.",
                    remediation="Pin the tag or, better, a digest.",
                ))

        # --- Privileged / capabilities ---
        if svc.get("privileged") is True:
            result.findings.append(Finding(
                rule_id=f"DC-003-{name}",
                title=f"{prefix}privileged: true",
                severity="critical",
                description="`privileged: true` gives the container almost all host capabilities, effectively "
                            "disabling most isolation.",
                remediation="Drop `privileged`. If you need a specific capability, grant it explicitly via "
                            "`cap_add`.",
            ))
        for cap in svc.get("cap_add", []) or []:
            if isinstance(cap, str) and cap.upper() in DANGEROUS_CAPS:
                result.findings.append(Finding(
                    rule_id=f"DC-004-{name}",
                    title=f"{prefix}Dangerous capability added: {cap}",
                    severity="high",
                    description=f"`{cap}` gives the container powerful privileges over the host.",
                    remediation="Remove the capability. If absolutely required, scope it to a specific workload "
                                "and review regularly.",
                ))
        if (svc.get("cap_drop") or []) == [] and not svc.get("privileged") and not svc.get("cap_add"):
            result.findings.append(Finding(
                rule_id=f"DC-005-{name}",
                title=f"{prefix}No cap_drop: [ALL] baseline",
                severity="low",
                description="Docker already drops most capabilities by default for non-privileged containers, "
                            "but being explicit (`cap_drop: [ALL]`, then `cap_add:` what you need) is the "
                            "modern best practice.",
                remediation="Add `cap_drop: [ALL]` and re-enable only the capabilities the service needs.",
            ))

        # --- network_mode: host ---
        if svc.get("network_mode") == "host":
            result.findings.append(Finding(
                rule_id=f"DC-006-{name}",
                title=f"{prefix}network_mode: host",
                severity="high",
                description="Host networking removes network namespace isolation; the container can bind any "
                            "port on the host and bypasses network policies.",
                remediation="Use the default bridge network (or a user-defined network) and publish only the "
                            "ports you need.",
            ))

        # --- pid: host / ipc: host ---
        if svc.get("pid") == "host":
            result.findings.append(Finding(
                rule_id=f"DC-007-{name}",
                title=f"{prefix}pid: host",
                severity="high",
                description="Sharing the host PID namespace lets the container see (and signal) all host processes.",
                remediation="Use the default (private) PID namespace.",
            ))
        if svc.get("ipc") == "host":
            result.findings.append(Finding(
                rule_id=f"DC-008-{name}",
                title=f"{prefix}ipc: host",
                severity="medium",
                description="Sharing the host IPC namespace allows the container to read host shared memory.",
                remediation="Use the default (private) IPC namespace.",
            ))

        # --- user / root ---
        user = svc.get("user")
        if user is None:
            result.findings.append(Finding(
                rule_id=f"DC-009-{name}",
                title=f"{prefix}No 'user' set (runs as root)",
                severity="critical",
                description="Without `user:`, the container runs as the user declared in the image — usually root.",
                remediation="Set `user: \"1000:1000\"` or whatever UID/GID the image's non-root account uses.",
            ))
        elif str(user).strip() in {"root", "0", "0:0"}:
            result.findings.append(Finding(
                rule_id=f"DC-010-{name}",
                title=f"{prefix}Service runs as root (user: {user})",
                severity="critical",
                description="The service is explicitly set to run as root.",
                remediation="Switch to a non-root user.",
            ))

        # --- read_only ---
        if not svc.get("read_only"):
            result.findings.append(Finding(
                rule_id=f"DC-011-{name}",
                title=f"{prefix}read_only filesystem not set",
                severity="low",
                description="A read-only root filesystem forces the container to declare writable volumes for any "
                            "place it needs to write, surfacing hidden writes and limiting blast radius.",
                remediation="Add `read_only: true` and explicitly mount writable volumes where needed.",
            ))

        # --- secrets in environment ---
        env = svc.get("environment")
        if env is not None:
            entries = env if isinstance(env, list) else (
                [f"{k}={v}" for k, v in env.items()] if isinstance(env, dict) else []
            )
            for entry in entries:
                if "=" not in entry:
                    continue
                k, v = entry.split("=", 1)
                if SECRET_ENV_KEY_RE.search(k) and v and v.strip() and not v.strip().startswith("${"):
                    result.findings.append(Finding(
                        rule_id=f"DC-012-{name}",
                        title=f"{prefix}Possible secret in environment: {k}",
                        severity="critical",
                        description=f"`environment: {k}=...` looks like a hard-coded credential. Compose files "
                                    "are routinely checked into source control, which leaks the value to anyone "
                                    "with repo access and to any history.",
                        remediation="Use an `.env` file with a placeholder + `env_file:`, Docker secrets, or an "
                                    "external secret store (Vault, AWS SSM, etc.).",
                    ))

        # --- env_file: .env checked in ---
        env_file = svc.get("env_file")
        if env_file:
            files = env_file if isinstance(env_file, list) else [env_file]
            for f in files:
                fname = f if isinstance(f, str) else (f.get("path") if isinstance(f, dict) else None)
                if fname and fname.endswith(".env"):
                    result.findings.append(Finding(
                        rule_id=f"DC-013-{name}",
                        title=f"{prefix}env_file references '.env'",
                        severity="medium",
                        description="`.env` files are commonly committed by accident. Make sure the file is in "
                                    "`.gitignore` and that CI doesn't bake it into images.",
                        remediation="Use a different filename and add it to `.gitignore`, or use Docker "
                                    "secrets/compose secrets.",
                    ))

        # --- ports / sensitive exposure ---
        published = _published_ports(svc.get("ports"))
        for p in published:
            host_ip = (p.get("host_ip") or "0.0.0.0")
            tgt = p.get("target")
            if tgt in SENSITIVE_HOST_PORTS and host_ip in ("0.0.0.0", "", None, "::"):
                result.findings.append(Finding(
                    rule_id=f"DC-014-{name}",
                    title=f"{prefix}Sensitive port {tgt} published to {host_ip}",
                    severity="critical",
                    description=f"Port {tgt} is a well-known management port and is exposed on all host "
                                "interfaces. This is a frequent entry point in container breaches.",
                    remediation="Bind to 127.0.0.1 (`127.0.0.1:{p.get('published')}:{tgt}`) or put the service "
                                "behind a reverse proxy with auth.",
                ))

        # --- volume mounts ---
        for v in svc.get("volumes", []) or []:
            if not isinstance(v, str):
                continue
            # split `src:dst[:mode]`
            parts = v.split(":")
            src = parts[0]
            if src in SENSITIVE_VOLUME_PATHS:
                result.findings.append(Finding(
                    rule_id=f"DC-015-{name}",
                    title=f"{prefix}Sensitive host path mounted: {src}",
                    severity="critical",
                    description=f"Mounting `{src}` from the host into the container gives the container access "
                                "to sensitive host data.",
                    remediation="Remove the bind mount. If the service needs a specific subpath, mount only that.",
                ))
            if src == "/var/run/docker.sock":
                result.findings.append(Finding(
                    rule_id=f"DC-016-{name}",
                    title=f"{prefix}Docker socket mounted",
                    severity="critical",
                    description="Mounting /var/run/docker.sock effectively gives the container root on the host: "
                                "anything that can talk to the Docker daemon can spawn privileged containers.",
                    remediation="Never mount the Docker socket. Use a sidecar/agent (e.g. Docker Socket Proxy, "
                                "Diode, or Telegraf) if you need container metrics.",
                ))

        # --- restart: always on critical services (operational smell, not vuln) ---
        if svc.get("restart") == "always" and svc.get("image") in {None, ""}:
            result.findings.append(Finding(
                rule_id=f"DC-017-{name}",
                title=f"{prefix}restart: always with no explicit image",
                severity="info",
                description="Combined with no pinned image, this will silently pull a new version on every "
                            "restart.",
                remediation="Pin the image and consider `restart: on-failure` for non-services.",
            ))

    # --- secrets block (compose-spec) ---
    if "secrets" in loaded and isinstance(loaded["secrets"], dict):
        for sec_name, sec_body in loaded["secrets"].items():
            if isinstance(sec_body, dict) and sec_body.get("file") and not sec_body.get("external"):
                result.findings.append(Finding(
                    rule_id=f"DC-SECRET-{sec_name}",
                    title=f"Inline secret: {sec_name}",
                    severity="medium",
                    description="`secrets:` entries with a `file:` source store the secret on disk alongside the "
                                "compose file. Make sure the file is gitignored.",
                    remediation="Prefer `external: true` and provision the secret out-of-band.",
                ))

    for f in result.findings:
        result.summary[f.severity] = result.summary.get(f.severity, 0) + 1
    result.summary["total"] = len(result.findings)
    return result, None


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    """Analyze a Dockerfile or docker-compose payload.

    Accepts either:
      - multipart form with field 'file' (plus optional 'kind')
      - JSON: {"kind": "dockerfile"|"compose", "content": "..."}
    """
    kind: str | None = None
    content: str | None = None
    filename: str = "pasted"

    if request.is_json:
        body = request.get_json(silent=True) or {}
        kind = body.get("kind")
        content = body.get("content", "")
        filename = body.get("filename") or filename
    else:
        if "file" in request.files:
            f = request.files["file"]
            filename = f.filename or filename
            content = f.read().decode("utf-8", errors="replace")
        else:
            content = request.form.get("content", "")
            filename = request.form.get("filename") or filename
        kind = request.form.get("kind") or _guess_kind(filename, content)

    kind = kind or _guess_kind(filename, content)

    if not content or not content.strip():
        return jsonify({"error": "Empty payload"}), 400
    if not kind:
        return jsonify({"error": "Cannot detect file kind. Pass kind=dockerfile|compose."}), 400

    if kind == "dockerfile":
        result = analyze_dockerfile(content)
        return jsonify({"filename": filename, **result.to_dict()})
    elif kind == "compose":
        result, err = analyze_compose(content)
        payload = {"filename": filename, **result.to_dict()}
        if err:
            payload["warning"] = err
        return jsonify(payload)
    else:
        return jsonify({"error": f"Unknown kind: {kind}"}), 400


def _guess_kind(filename: str, content: str) -> str | None:
    fn = filename.lower()
    if fn in {"dockerfile"} or fn.startswith("dockerfile.") or fn.endswith(".dockerfile"):
        return "dockerfile"
    if "compose" in fn and (fn.endswith(".yml") or fn.endswith(".yaml")):
        return "compose"
    # Heuristic by content
    head = content.lstrip().lower()
    if head.startswith("from ") or re.search(r"^\s*(from|run|copy|add|cmd|entrypoint|env|arg|expose|user|workdir)\b",
                                            content, re.MULTILINE | re.IGNORECASE):
        # Only treat as Dockerfile if we see a Dockerfile directive AND no `services:` map.
        if re.search(r"^\s*(services|version)\s*:", content, re.MULTILINE):
            return "compose"
        return "dockerfile"
    if re.search(r"^\s*services\s*:", content, re.MULTILINE):
        return "compose"
    return None


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/sample")
def sample():
    """Serve one of the bundled sample files for the UI's 'Load sample' button."""
    which = request.args.get("which", "Dockerfile.bad")
    # Resolve relative to the app file, with a defense against path traversal.
    base = Path(app.root_path) / "samples"
    target = (base / which).resolve()
    if not str(target).startswith(str(base.resolve())) or not target.is_file():
        return jsonify({"error": "sample not found"}), 404
    try:
        content = target.read_text(encoding="utf-8")
    except OSError as e:
        return jsonify({"error": f"cannot read sample: {e}"}), 500
    return jsonify({"filename": target.name, "content": content})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
