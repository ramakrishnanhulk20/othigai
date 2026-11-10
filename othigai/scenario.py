"""Loads a scenario file and refuses anything that could point a child at something real.

A scenario holds wording only. Every path, address and value comes from placeholders the plugin
fills in at run time, so obeying a trap to the letter can only touch this run's fake assets.

Covers literal targets in the wording, including the bare names of real secret files. Does not
cover a paraphrased request for something harmful, or a look-alike spelling of one of those names.
The gate stops both when the child acts on them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SCENARIO_FOLDER = Path(__file__).resolve().parents[1] / "scenarios"
MAX_FILE_BYTES = 64 * 1024
MAX_TEXT_CHARS = 8 * 1024

_FIELDS = {"id", "source", "errand", "email_file", "key_file", "key_body", "trap_email", "clean_email"}
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_FILE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\.txt")
_SOURCE = re.compile(r"https://github\.com/NousResearch/hermes-agent/issues/[0-9]{1,8}")
_PLACEHOLDER = re.compile(r"\{[^{}\s]*\}")
_EMAIL_DOMAIN = re.compile(r"@([A-Za-z0-9.-]+)")
_REAL_SECRET_NAMES = (".env", "auth.json", "id_rsa", "id_ed25519", ".npmrc", ".netrc", "credentials.json", ".aws")
_SECRET_NAME_CHOICES = "|".join(re.escape(name) for name in _REAL_SECRET_NAMES)
_LITERAL_TARGETS = (
    re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    re.compile(r"\blocalhost\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z]:[\\/]"),
    re.compile(r"(?:^|\s)[/~\\]"),
    re.compile(r"\.\."),
    re.compile(r"\\\\"),
    # Whole names only, so `oauth.json` and `.environment` pass. A dot after the name still counts,
    # because that is how a sentence ends, and `.env.local` is a secret file too.
    re.compile(rf"(?<![A-Za-z0-9_.-])(?:{_SECRET_NAME_CHOICES})(?![A-Za-z0-9_-])", re.IGNORECASE),
)
_REQUIRED_PLACEHOLDERS = {
    "errand": {"{email_path}"},
    "key_body": {"{marker}"},
    "trap_email": {"{key_path}", "{listener_url}"},
    "clean_email": set(),
}
_ALLOWED_PLACEHOLDERS = {
    "errand": {"{email_path}"},
    "key_body": {"{marker}"},
    "trap_email": {"{key_path}", "{listener_url}"},
    "clean_email": {"{key_path}", "{listener_url}"},
}


class ScenarioError(ValueError):
    """A scenario file is missing or fails validation."""


@dataclass(frozen=True)
class Scenario:
    id: str
    source: str
    errand: str
    email_file: str
    key_file: str
    key_body: str
    trap_email: str
    clean_email: str


def _check_text(field_name: str, text: object) -> None:
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS:
        raise ScenarioError(f"{field_name} must be text of a sensible size")
    found = set(_PLACEHOLDER.findall(text))
    if found - _ALLOWED_PLACEHOLDERS[field_name] or _REQUIRED_PLACEHOLDERS[field_name] - found:
        raise ScenarioError(f"{field_name} has the wrong placeholders")
    wording = _PLACEHOLDER.sub(" ", text)
    if any(pattern.search(wording) for pattern in _LITERAL_TARGETS):
        raise ScenarioError(f"{field_name} names a literal target")
    if any(not domain.lower().endswith(".example") for domain in _EMAIL_DOMAIN.findall(wording)):
        raise ScenarioError(f"{field_name} names a real mail domain")


def validate_scenario(data: object) -> Scenario:
    """Turn parsed YAML into a Scenario, or raise ScenarioError. Unknown or missing fields fail."""
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise ScenarioError("a scenario must hold exactly the known fields")
    if not isinstance(data["id"], str) or not _ID.fullmatch(data["id"]):
        raise ScenarioError("bad id")
    if not isinstance(data["source"], str) or not _SOURCE.fullmatch(data["source"]):
        raise ScenarioError("a scenario must cite its tracker issue")
    names = data["email_file"], data["key_file"]
    if not all(isinstance(name, str) and _FILE_NAME.fullmatch(name) for name in names) or names[0] == names[1]:
        raise ScenarioError("bad file names")
    for field_name in _ALLOWED_PLACEHOLDERS:
        _check_text(field_name, data[field_name])
    return Scenario(**data)


def _parse_yaml(text: str) -> object:
    """Hermes ships ruamel.yaml, not PyYAML. The safe type builds plain data and never objects."""
    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.error import YAMLError
    except ImportError as error:
        raise ScenarioError("this Hermes has no YAML library") from error
    try:
        return YAML(typ="safe", pure=True).load(text)
    except YAMLError as error:
        raise ScenarioError("scenario file does not parse") from error


def load_scenario(scenario_id: str, folder: Path = SCENARIO_FOLDER) -> Scenario:
    """Load one shipped scenario by id. The id must match the file it came from."""
    if not isinstance(scenario_id, str) or not _ID.fullmatch(scenario_id):
        raise ScenarioError("bad id")
    path = folder / f"{scenario_id}.yaml"
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ScenarioError("no such scenario") from error
    if len(raw) > MAX_FILE_BYTES:
        raise ScenarioError("scenario file too large")
    try:
        scenario = validate_scenario(_parse_yaml(raw.decode("utf-8")))
    except UnicodeDecodeError as error:
        raise ScenarioError("scenario file does not parse") from error
    if scenario.id != scenario_id:
        raise ScenarioError("scenario id does not match its file name")
    return scenario


def shipped_scenario_ids(folder: Path = SCENARIO_FOLDER) -> list[str]:
    return sorted(path.stem for path in folder.glob("*.yaml"))
