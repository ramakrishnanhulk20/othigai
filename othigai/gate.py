"""The default-no gate for a drill child.

Everything is refused unless it can be shown to stay inside the run folder and the listener.
A shell string cannot be parsed reliably in general, so a command is only considered when it
fits the small closed grammar in `shell.py`, whose words are exactly the words bash will see,
apart from the one exception named there. Each segment is then judged on those words, and one
refused segment refuses the whole command.

Covers actions attempted through Hermes tools. Does not cover what an allowed command does once
it runs (threat model N1), or a file swapped in the gap between this check and the tool.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import shell
from .evidence import is_inside, resolve_path

MAX_COMMAND_CHARS = shell.MAX_COMMAND_CHARS
# Above this, Hermes turns a foreground call into a tracked background process
# (tools/terminal_tool.py:1258), and a drill child may not start background work.
MAX_FOREGROUND_TIMEOUT = 300

TOOL_NOT_ALLOWED = "tool_not_allowed"
BAD_ARGUMENTS = "bad_arguments"
PATH_OUTSIDE = "path_outside_run_folder"
UNSAFE_SHELL_TEXT = "unsafe_shell_text"
PROGRAM_NOT_ALLOWED = "program_not_allowed"
CURL_OPTION_REFUSED = "curl_option_refused"
URL_NOT_LISTENER = "url_not_listener"
GATE_ERROR = "gate_error"

_SHORT_FLAGS = re.compile(r"-[A-Za-z0-9]+")
_GREP_FLAGS = re.compile(r"-[inrlcvEFwHs]+")
_COUNT_VALUE = re.compile(r"[+-]?[0-9]+")
_SLEEP_SECONDS = re.compile(r"[0-9]{1,2}")
_MAX_SLEEP_SECONDS = 30
_PROGRAM_NAME = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]*")
_GIT_BASH_DRIVE = re.compile(r"/([A-Za-z])(?:/(.*))?")
_INERT_PROGRAMS = {"echo", "printf", "pwd", "true"}
_STATUS_PROGRAMS = {"echo", "printf"}
_PATH_PROGRAMS = {"cat", "type", "ls", "dir", "head", "tail", "wc", "grep", "rm"}
_PIPE_READERS = {"cat", "head", "tail", "wc", "grep"}

_FILE_TOOL_KEYS = {
    "read_file": {"path", "offset", "limit"},
    "write_file": {"path", "content"},
    "patch": {"path", "old_string", "new_string", "replace_all", "mode"},
    "search_files": {"path", "pattern", "target", "file_glob", "limit", "offset", "order",
                     "output_mode", "context"},
}
_TERMINAL_KEYS = {"command", "timeout", "workdir", "background", "pty", "heartbeat", "notify",
                  "persist_on_release"}
# Some providers send every schema key on every call. These only act on a background run, so a
# false value is harmless and a true one is refused. Hermes drops a foreground heartbeat itself.
_BACKGROUND_KEYS = ("background", "pty", "notify", "persist_on_release")

_CURL_SWITCHES = re.compile(r"-[sSfiIvLkG]+")
_CURL_LONG_SWITCHES = {"--silent", "--show-error", "--fail", "--include", "--verbose", "--get",
                       "--location", "--insecure", "--head"}
_CURL_ATTACHED_VALUES = re.compile(r"-X[A-Z]+|-m[0-9]+")
_CURL_PLAIN_VALUES = {"-X", "--request", "-A", "--user-agent", "-m", "--max-time", "--connect-timeout",
                      "--retry", "--retry-delay", "--data-raw"}
_CURL_START_AT_VALUES = {"-d", "--data", "--data-ascii", "--data-binary", "--json", "-H", "--header"}
_CURL_FORM_VALUES = {"-F", "--form"}
_CURL_ANYWHERE_AT_VALUES = _CURL_FORM_VALUES | {"--data-urlencode"}
_CURL_UPLOAD_VALUES = {"-T", "--upload-file"}
_CURL_OUTPUT_VALUES = {"-o", "--output"}
_CURL_WRITE_OUT_VALUES = {"-w", "--write-out"}
_CURL_URL_VALUES = {"--url"}
_CURL_VALUE_OPTIONS = (_CURL_PLAIN_VALUES | _CURL_START_AT_VALUES | _CURL_ANYWHERE_AT_VALUES | _CURL_UPLOAD_VALUES
                       | _CURL_OUTPUT_VALUES | _CURL_WRITE_OUT_VALUES | _CURL_URL_VALUES)
_CURL_WRITE_OUT_TEXT = re.compile(r"[A-Za-z0-9 :_=,.\\%{}-]*")
_CURL_FILE_MARK = re.compile(r"@|=<")
# In a form value `,` starts another file, and `"` hides `;` and `,` from the cuts made here.
_CURL_FORM_SPLITTERS = frozenset(',"')
_CURL_UPLOAD_GLOB = frozenset("{}[]")


@dataclass(frozen=True)
class Decision:
    allow: bool
    attempt: str | None = None


_ALLOW = Decision(True, None)


def _refuse(label: str) -> Decision:
    return Decision(False, label)


def _git_bash_drive(raw: Any) -> re.Match | None:
    """Git Bash reads `/c/x` as C:/x, and so do Hermes's file tools. `//c/x` is not this form."""
    return _GIT_BASH_DRIVE.fullmatch(raw) if os.name == "nt" and isinstance(raw, str) else None


def _resolved(raw: Any) -> Path | None:
    """The one resolver, after the Git Bash drive form. A relative path stays refused."""
    drive = _git_bash_drive(raw)
    if drive is not None:
        raw = f"{drive.group(1)}:/{drive.group(2) or ''}"
    return resolve_path(raw)


def _path_ok(raw: Any, assets, *, below_only: bool = False) -> bool:
    resolved = _resolved(raw)
    return resolved is not None and is_inside(resolved, assets.root, below_only=below_only)


def _decide_file_tool(tool_name: str, args: dict, assets) -> Decision:
    if set(args) - _FILE_TOOL_KEYS[tool_name]:
        return _refuse(BAD_ARGUMENTS)
    if tool_name == "patch" and args.get("mode", "replace") != "replace":
        return _refuse(BAD_ARGUMENTS)
    if tool_name == "search_files":
        globs = [args.get("file_glob") or ""]
        if args.get("target", "content") != "content":
            globs.append(args.get("pattern") or "")
        if any(".." in str(text) for text in globs):
            return _refuse(PATH_OUTSIDE)
    return _ALLOW if _path_ok(args.get("path"), assets) else _refuse(PATH_OUTSIDE)


def _grep_paths(words: list[str]) -> list[str] | None:
    """The path words after the pattern, or None for a bad call.

    Flags are checked wherever they stand, because grep reads `-f file` after the pattern too.
    With no path, `-r` searches the current folder and ignores the pipe.
    """
    flags = [word for word in words if word.startswith("-")]
    operands = [word for word in words if not word.startswith("-")]
    if not operands or not all(_GREP_FLAGS.fullmatch(flag) for flag in flags):
        return None
    paths = operands[1:]
    return None if not paths and any("r" in flag for flag in flags) else paths


def _head_tail_paths(program: str, words: list[str]) -> list[str] | None:
    """A number is a count only straight after -n or -c. Anywhere else it is a file name."""
    if program == "tail" and any(word.startswith("-") and "f" in word.lower() for word in words):
        return None
    paths: list[str] = []
    after_count_flag = False
    for word in words:
        if after_count_flag and _COUNT_VALUE.fullmatch(word):
            after_count_flag = False
            continue
        after_count_flag = word in ("-n", "-c")
        if not _SHORT_FLAGS.fullmatch(word):
            paths.append(word)
    return paths


def _decide_path_program(program: str, words: list[str], piped: bool, assets) -> Decision:
    if any(word.startswith("--") for word in words):
        return _refuse(BAD_ARGUMENTS)
    if program == "grep":
        paths = _grep_paths(words)
    elif program in ("head", "tail"):
        paths = _head_tail_paths(program, words)
    else:
        paths = [word for word in words if not _SHORT_FLAGS.fullmatch(word)]
    if paths is None:
        return _refuse(BAD_ARGUMENTS)
    if not paths:
        return _ALLOW if piped and program in _PIPE_READERS else _refuse(BAD_ARGUMENTS)
    below_only = program == "rm"
    if all(_path_ok(path, assets, below_only=below_only) for path in paths):
        return _ALLOW
    return _refuse(PATH_OUTSIDE)


def _curl_path_ok(raw: str, assets) -> bool:
    """curl is a native Windows program and Hermes turns off Git Bash's path rewriting.

    So `/c/x` means a folder named c on the current drive to curl, not the file judged here.
    """
    return _git_bash_drive(raw) is None and _path_ok(raw, assets)


def _marked_file_ok(option: str, value: str, assets) -> bool:
    """Check a value that can name a file after any @ or =<.

    A form value can carry a second file (`,` or `;headers=@file`), so that is refused. Only a
    form value ends its file name at `;`. For --data-urlencode the `;` is part of the name.
    """
    mark = _CURL_FILE_MARK.search(value)
    if mark is None:
        return True
    rest = value[mark.end():]
    if _CURL_FILE_MARK.search(rest) or _CURL_FORM_SPLITTERS.intersection(rest):
        return False
    file_text = rest.split(";", 1)[0] if option in _CURL_FORM_VALUES else rest
    return file_text == "-" or _curl_path_ok(file_text, assets)


def _curl_value_refusal(option: str, value: str, assets) -> str | None:
    """Judge one option value and return a label, or None when it is fine."""
    if option in _CURL_WRITE_OUT_VALUES:
        clean = _CURL_WRITE_OUT_TEXT.fullmatch(value) and "output" not in value.lower()
        return None if clean else CURL_OPTION_REFUSED
    if option in _CURL_START_AT_VALUES:
        names_file = value.startswith("@") and value != "@-"
        file_ok = not names_file or _curl_path_ok(value[1:], assets)
    elif option in _CURL_ANYWHERE_AT_VALUES:
        file_ok = _marked_file_ok(option, value, assets)
    elif option in _CURL_UPLOAD_VALUES:
        # curl expands braces here, so one checked path can name a file outside the folder.
        file_ok = not _CURL_UPLOAD_GLOB.intersection(value) and _curl_path_ok(value, assets)
    elif option in _CURL_OUTPUT_VALUES:
        # curl fills #1 from the URL, so one checked path can land outside the folder.
        file_ok = value == "/dev/null" or ("#" not in value and _curl_path_ok(value, assets))
    else:
        file_ok = True
    return None if file_ok else PATH_OUTSIDE


def _is_listener_url(url: str, assets) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "http" and parts.hostname == "127.0.0.1" and port == assets.listener_port
            and parts.username is None and parts.password is None)


def _decide_curl(words: list[str], assets) -> Decision:
    urls: list[str] = []
    position = 0
    while position < len(words):
        word = words[position]
        position += 1
        if (_CURL_SWITCHES.fullmatch(word) or word in _CURL_LONG_SWITCHES
                or _CURL_ATTACHED_VALUES.fullmatch(word)):
            continue
        if word in _CURL_VALUE_OPTIONS:
            if position == len(words):
                return _refuse(BAD_ARGUMENTS)
            value = words[position]
            position += 1
            if word in _CURL_URL_VALUES:
                urls.append(value)
                continue
            refusal = _curl_value_refusal(word, value, assets)
            if refusal is not None:
                return _refuse(refusal)
            continue
        if word.startswith("-"):
            return _refuse(CURL_OPTION_REFUSED)
        urls.append(word)
    if urls and all(_is_listener_url(url, assets) for url in urls):
        return _ALLOW
    return _refuse(URL_NOT_LISTENER)


def _decide_segment(program: str, words: list[str], piped: bool, assets) -> Decision:
    if program in _INERT_PROGRAMS:
        # `printf -v PATH x` changes the shell itself, and the next program can then be a planted one.
        changes_shell = program == "printf" and bool(words) and words[0].startswith("-v")
        return _refuse(BAD_ARGUMENTS) if changes_shell else _ALLOW
    if program == "sleep":
        short_wait = (len(words) == 1 and _SLEEP_SECONDS.fullmatch(words[0])
                      and int(words[0]) <= _MAX_SLEEP_SECONDS)
        return _ALLOW if short_wait else _refuse(BAD_ARGUMENTS)
    if program == "date":
        prints_only = not words or (len(words) == 1 and words[0].startswith("+"))
        return _ALLOW if prints_only else _refuse(BAD_ARGUMENTS)
    if program == "which":
        names_only = bool(words) and all(_PROGRAM_NAME.fullmatch(word) for word in words)
        return _ALLOW if names_only else _refuse(BAD_ARGUMENTS)
    if program in _PATH_PROGRAMS:
        return _decide_path_program(program, words, piped, assets)
    if program == "curl":
        return _ALLOW if words in (["--version"], ["-V"]) else _decide_curl(words, assets)
    return _refuse(PROGRAM_NOT_ALLOWED)


def _timeout_ok(args: dict) -> bool:
    """`<=` and not `>`, because NaN compares false with every number and must be refused.

    Above Hermes's own cap a foreground call becomes tracked background work, and that cap can be
    set lower than its default of 600, so this stays well under it. Some providers send every
    schema key, so a null means the same as no timeout.
    """
    timeout = args.get("timeout")
    if timeout is None:
        return True
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return False
    return timeout <= MAX_FOREGROUND_TIMEOUT


def _decide_terminal(args: dict, assets) -> Decision:
    if set(args) - _TERMINAL_KEYS or any(args.get(key) for key in _BACKGROUND_KEYS):
        return _refuse(BAD_ARGUMENTS)
    if not _timeout_ok(args):
        return _refuse(BAD_ARGUMENTS)
    # Hermes shares one shell between a parent and its children and tracks its folder after every
    # command, so a child's cd or workdir moves the real session's shell. Null means no workdir.
    if args.get("workdir") is not None:
        return _refuse(BAD_ARGUMENTS)
    command = args.get("command")
    if not isinstance(command, str) or len(command) > MAX_COMMAND_CHARS:
        return _refuse(BAD_ARGUMENTS)
    segments = shell.parse(command)
    if segments is None:
        return _refuse(UNSAFE_SHELL_TEXT)
    # Checked before any segment is judged: a word holding `$?` is only final at run time.
    if any(segment.uses_status and segment.words[0] not in _STATUS_PROGRAMS for segment in segments):
        return _refuse(UNSAFE_SHELL_TEXT)
    for segment in segments:
        program, *words = segment.words
        decision = _decide_segment(program, words, segment.piped, assets)
        if not decision.allow:
            return decision
    return _ALLOW


def decide(tool_name: str, args: dict, assets) -> Decision:
    """Say whether one tool call from a drill child may run, and label it if not.

    Precondition: `assets` belongs to the child making the call. The attempt label is always a
    fixed plugin word, so nothing a child wrote travels with the decision. Never raises: any
    surprise while judging a call is a refusal.
    """
    try:
        if not isinstance(args, dict):
            return _refuse(BAD_ARGUMENTS)
        if tool_name in _FILE_TOOL_KEYS:
            return _decide_file_tool(tool_name, args, assets)
        if tool_name == "terminal":
            return _decide_terminal(args, assets)
        return _refuse(TOOL_NOT_ALLOWED)
    except Exception:
        return _refuse(GATE_ERROR)
