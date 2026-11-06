"""Turn one shell command into the exact words bash will run, or refuse it.

The grammar is closed: text it does not name is refused, so a shell feature nobody thought of is
a refusal and not a surprise. This is safe because outside single quotes the only expansion
allowed is `$?`. With nothing else left for bash to expand, split or glob, the words here are
exactly the words bash will see, and there is no second parser to disagree with. `shlex` is not
used because it accepts text this grammar must refuse.

`$?` is the one expansion allowed. It is safe because it expands to a number, and the gate lets
only echo and printf use it, so no judged word can change. A word keeps the two characters as
written, and `uses_status` marks its segment. Single-quoted `$?` is marked too, which can only
refuse more.

A doubled backslash is refused even inside single quotes. Hermes starts bash with `-c`, and the
Windows command line halves a doubled backslash on the way, so those words would differ from the
words bash receives.

Covers how the text splits into segments and words. Does not cover what those words mean to a
program, which the gate judges, or an allowed command that does something else at run time
(threat model N1).
"""

from __future__ import annotations

import string
from dataclasses import dataclass

MAX_COMMAND_CHARS = 4096

_PLAIN_CHARS = frozenset(string.ascii_letters + string.digits + "_./:@=,+-")
_EXIT_STATUS = "$?"
_REFUSED_IN_DOUBLE_QUOTES = frozenset("$`\\!")
# Bash keeps both characters of these, so the word is still the text as written. Before anything
# else a backslash can change the word (`"\\"` is one backslash) or hide the closing quote.
_KEPT_AFTER_BACKSLASH = frozenset("ntr")
_REDIRECTS = ("2>&1", "2>/dev/null", ">/dev/null", "1>/dev/null", "&>/dev/null")
_OPERATORS = ("&&", "||", ";", "|")
_AFTER_REDIRECT = frozenset(" ;|&")


@dataclass(frozen=True)
class Segment:
    """One simple command. `piped` means it reads the previous segment through `|`.

    `uses_status` means a word holds `$?`, so that word is not final until bash runs it.
    """

    words: tuple[str, ...]
    piped: bool
    uses_status: bool = False


def _segment(words: list[str], piped: bool) -> Segment:
    return Segment(tuple(words), piped, any(_EXIT_STATUS in word for word in words))


def _redirect_end(text: str, start: int) -> int | None:
    """Only a whole token counts: `2>&1x` writes to a file and `2>/dev/null'x'` to another."""
    for token in _REDIRECTS:
        end = start + len(token)
        if text.startswith(token, start) and (end == len(text) or text[end] in _AFTER_REDIRECT):
            return end
    return None


def _closing_quote(text: str, start: int) -> int | None:
    quote = text[start]
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == quote:
            return index
        if quote == "'" and text.startswith("\\\\", index):
            return None
        if quote == '"' and character == "\\" and text[index + 1:index + 2] in _KEPT_AFTER_BACKSLASH:
            index += 2
            continue
        if quote == '"' and text.startswith(_EXIT_STATUS, index):
            index += len(_EXIT_STATUS)
            continue
        if quote == '"' and character in _REFUSED_IN_DOUBLE_QUOTES:
            return None
        index += 1
    return None


def _read_word(text: str, start: int) -> tuple[str, int] | None:
    """Join adjacent parts as bash does. Returns the word and where it stopped, or None."""
    parts: list[str] = []
    position = start
    while position < len(text):
        character = text[position]
        if character == "'" or character == '"':
            closing = _closing_quote(text, position)
            if closing is None:
                return None
            parts.append(text[position + 1:closing])
            position = closing + 1
        elif text.startswith(_EXIT_STATUS, position):
            parts.append(_EXIT_STATUS)
            position += len(_EXIT_STATUS)
        elif character in _PLAIN_CHARS:
            end = position
            while end < len(text) and text[end] in _PLAIN_CHARS:
                end += 1
            parts.append(text[position:end])
            position = end
        else:
            break
    return ("".join(parts), position) if parts else None


def parse(command: str) -> list[Segment] | None:
    """Split a command into segments of final words, or None when it is outside the grammar.

    Precondition: none, any value is accepted. Never raises. The allowed redirects are dropped,
    because they change no word and reach no file. A segment holding only a redirect counts as
    empty.
    """
    if not isinstance(command, str) or len(command) > MAX_COMMAND_CHARS or not command.strip():
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        return None
    segments: list[Segment] = []
    words: list[str] = []
    piped = redirected = False
    last_operator = None
    at_boundary = True
    position = 0
    while position < len(command):
        if command[position] == " ":
            position += 1
            at_boundary = True
            continue
        redirect_end = _redirect_end(command, position) if at_boundary else None
        if redirect_end is not None:
            position = redirect_end
            redirected, at_boundary = True, False
            continue
        operator = next((item for item in _OPERATORS if command.startswith(item, position)), None)
        if operator is not None:
            if not words:
                return None
            segments.append(_segment(words, piped))
            words, redirected, piped, last_operator = [], False, operator == "|", operator
            position += len(operator)
            at_boundary = True
            continue
        word = _read_word(command, position)
        if word is None:
            return None
        words.append(word[0])
        position = word[1]
        at_boundary = False
    if words:
        segments.append(_segment(words, piped))
    elif last_operator != ";" or redirected:
        return None
    return segments
