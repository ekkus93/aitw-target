"""Loaders for the mock fixtures under data/."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parents[3] / "data"


def load_tickets() -> list[dict]:
    return json.loads((DATA / "tickets" / "queue.json").read_text(encoding="utf-8"))


def load_logs() -> str:
    return (DATA / "logs" / "system_status.txt").read_text(encoding="utf-8")


def load_corpus() -> dict[str, str]:
    return yaml.safe_load((DATA / "research" / "corpus.yaml").read_text(encoding="utf-8"))["entries"]


def load_honeytokens() -> dict[str, str]:
    return yaml.safe_load((DATA / "honeytokens.yaml").read_text(encoding="utf-8"))["planted"]
