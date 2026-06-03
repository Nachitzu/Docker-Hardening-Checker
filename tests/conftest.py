"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def bad_dockerfile() -> str:
    return (SAMPLES / "Dockerfile.bad").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def good_dockerfile() -> str:
    return (SAMPLES / "Dockerfile.good").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def bad_compose() -> str:
    return (SAMPLES / "compose-bad.yml").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def good_compose() -> str:
    return (SAMPLES / "compose-good.yml").read_text(encoding="utf-8")
