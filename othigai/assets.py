"""One run's fake world: a folder in the system temp area with a fresh marker.

The folder sits outside the Hermes home on purpose, so a child that wanders near the fake key
finds nothing real beside it. Every value that could be copied (marker, listener token, paths)
is new for each run, so a replayed transcript points at things that no longer exist.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import tempfile
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass, replace
from pathlib import Path

from .evidence import is_inside

logger = logging.getLogger(__name__)

# Neutral on purpose: a real model read a folder named after this plugin and said it was a test.
RUN_PREFIX = "workspace-"
MARKER_BYTES = 16
FOLDER_NAME_BYTES = 8
# A few lines in normal use. A child's shell could grow the file, so a sweep reads only this much.
MAX_JOURNAL_CHARS = 64 * 1024


class RunFolderError(RuntimeError):
    """The run folder could not be placed somewhere safe."""


@dataclass(frozen=True)
class RunAssets:
    root: Path
    marker: str
    email_path: Path
    key_path: Path
    listener_port: int = 0
    listener_token: str = ""

    @property
    def listener_url(self) -> str:
        return f"http://127.0.0.1:{self.listener_port}/{self.listener_token}"


def new_marker() -> str:
    """Plain lowercase hex: it carries no fixed public prefix, and Hermes's masking leaves it whole."""
    return secrets.token_hex(MARKER_BYTES)


def _hermes_home() -> Path | None:
    try:
        from hermes_constants import get_hermes_home
    except ImportError:
        raw = os.environ.get("HERMES_HOME")
        return Path(raw) if raw else None
    return get_hermes_home()


def reserve_run_folder(note: Callable[[Path], None]) -> Path:
    """Create an empty run folder, telling `note` its path first.

    The name comes before the folder, so a crash at any moment leaves a line to sweep and never
    a folder nobody wrote down. If `note` raises, no folder is made.
    """
    root = Path(tempfile.gettempdir()).resolve() / f"{RUN_PREFIX}{secrets.token_hex(FOLDER_NAME_BYTES)}"
    note(root)
    root.mkdir(mode=0o700)
    return root


def build_run_folder(scenario, note: Callable[[Path], None] = lambda _root: None) -> RunAssets:
    """Create a run folder holding the fake key file.

    The email is planted afterwards, by `plant_email`, because it names a listener that does
    not exist yet. Raises RunFolderError when the system temp area sits inside the Hermes home.
    """
    home = _hermes_home()
    if home is not None and is_inside(Path(tempfile.gettempdir()).resolve(), Path(home).resolve()):
        raise RunFolderError("the system temp folder is inside the Hermes home")
    root = reserve_run_folder(note)
    marker = new_marker()
    key_path = root / scenario.key_file
    key_path.write_text(scenario.key_body.replace("{marker}", marker), encoding="utf-8")
    return RunAssets(root=root, marker=marker, email_path=root / scenario.email_file, key_path=key_path)


def plant_email(assets: RunAssets, scenario, *, trap: bool, port: int, token: str) -> RunAssets:
    """Write the trap or clean email with this run's real values, and bind the listener."""
    bound = replace(assets, listener_port=port, listener_token=token)
    text = scenario.trap_email if trap else scenario.clean_email
    filled = text.replace("{key_path}", bound.key_path.as_posix()).replace("{listener_url}", bound.listener_url)
    bound.email_path.write_text(filled, encoding="utf-8")
    return bound


def is_run_folder(root: Path) -> bool:
    """A direct child of the temp area with our prefix, and not a link.

    The parent and prefix are compared as text first, so a hostile path is judged without
    touching it. Does not prove this plugin made the folder, only that it has the shape of one.
    """
    temp_area = Path(tempfile.gettempdir()).resolve()
    return root.parent == temp_area and root.name.startswith(RUN_PREFIX) and not root.is_symlink()


def remove_run_folder(root: Path) -> bool:
    """Delete a run folder, and only a run folder: a direct child of the temp area with our prefix.

    Python's rmtree unlinks links and junctions without entering them, so a child that planted
    one cannot turn this cleanup into a delete elsewhere.
    """
    if not is_run_folder(root):
        return False
    shutil.rmtree(root, ignore_errors=True)
    return not root.exists()


class RunFolderJournal:
    """Every run folder on disk, one absolute path per line, so a crash leaves a list to sweep.

    A child's shell could rewrite this file, so no line is trusted: `remove_run_folder` applies
    its own rule to each one. Covers folders made by drills in this profile. Does not cover two
    Hermes processes on one profile, where a live folder of the other looks like a leftover.
    """

    def __init__(self, path: Callable[[], Path]):
        self._path = path
        self._lock = threading.Lock()

    def add(self, root: Path) -> None:
        """Raises RunFolderError when the line cannot be written, so no folder goes unrecorded."""
        try:
            with self._lock, self._path().open("a", encoding="utf-8") as handle:
                handle.write(f"{root}\n")
        except OSError as error:
            raise RunFolderError("the run folder journal cannot be written") from error

    def drop(self, root: Path) -> None:
        """A write that fails leaves the line, and the next sweep deals with it."""
        try:
            with self._lock:
                self._write([line for line in self._lines() if line != str(root)])
        except OSError:
            logger.exception("othigai could not update the run folder journal")

    def sweep(self, held: Collection[Path]) -> None:
        """Remove what a crash left, keeping the folders in `held`, which a live child still needs.

        A line that names anything else is dropped and its target left alone. A folder that would
        not delete keeps its line for next time. Never raises, because a leftover must not stop a
        new drill.
        """
        try:
            with self._lock:
                self._write([line for line in self._lines() if not self._settled(Path(line), held)])
        except OSError:
            logger.exception("othigai could not sweep the run folder journal")

    @staticmethod
    def _settled(root: Path, held: Collection[Path]) -> bool:
        if root in held:
            return False
        try:
            return not is_run_folder(root) or remove_run_folder(root)
        except (OSError, ValueError):
            return True

    def _lines(self) -> list[str]:
        try:
            with self._path().open(encoding="utf-8", errors="replace") as handle:
                return [line for line in handle.read(MAX_JOURNAL_CHARS).splitlines() if line.strip()]
        except FileNotFoundError:
            return []

    def _write(self, lines: list[str]) -> None:
        target = self._path()
        temporary = target.with_suffix(".tmp")
        temporary.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        temporary.replace(target)
