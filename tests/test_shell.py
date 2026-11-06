"""The closed shell grammar: what it refuses, what it accepts, and that its words match bash.

Does not cover: what the gate does with the words (tests/test_gate.py), or an allowed command
that does something else at run time (threat model N1).
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from othigai.shell import MAX_COMMAND_CHARS, Segment, parse


def words_of(command):
    return [list(segment.words) for segment in parse(command)]


def real_bash():
    if os.name == "nt":
        return str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe")
    return shutil.which("bash")


def run_in_bash(command):
    return subprocess.run([real_bash(), "-c", command], capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("command", [
    "echo $(id)", "echo `id`", 'echo "$HOME"', 'echo "a\\b"', "cat <(ls)", "cat < x", "echo hi > x", "echo hi & ",
    "a &&", "; a", "a ;; b", "'unbalanced", "ls *", "ls ~", "echo #x", "a=b$c", "a\nb",
])
def test_the_exact_refusals(command):
    assert parse(command) is None


@pytest.mark.parametrize("command", [
    "echo $HOME", "echo ${HOME}", "echo a\\ b", "echo (a)", "(a)", "a & b", "a&", "echo ?", "ls [ab]", "ls a]",
    "echo {a,b}", "echo }", "echo !x", "echo %x", "echo ^x", "echo '", 'echo "', "echo 'a", 'echo "a', "echo a'b",
    'echo "a!b"', 'echo "a`b"', "echo caf\u00e9", "echo \uff07a\uff07", "cat <<EOF", "a >> b", "a |& b", "a ;& b",
])
def test_everything_else_outside_quotes_is_refused(command):
    assert parse(command) is None


@pytest.mark.parametrize("command", [
    "", " ", "   ", "\t", "a\tb", "a\rb", "'a\nb'", "'a\tb'", '"a\x7fb"', "a\x00b", "a\x7f", "\u00a0",
])
def test_empty_text_and_control_characters_are_refused_even_inside_quotes(command):
    assert parse(command) is None


@pytest.mark.parametrize("command", [
    ";", "|", "||", "&&", "| a", "|| a", "&& a", "a |", "a ||", "a | | b", "a || | b", "a ||| b", "a &&& b",
    "a ; ; b", "a ;;", "a ; ;", ";;",
])
def test_empty_segments_are_refused(command):
    assert parse(command) is None


@pytest.mark.parametrize("value", [None, 5, b"ls", ["ls"]])
def test_values_that_are_not_text_are_refused_without_raising(value):
    assert parse(value) is None


def test_the_length_limit_is_exact():
    assert parse("a" * MAX_COMMAND_CHARS) == [Segment(("a" * MAX_COMMAND_CHARS,), False)]
    assert parse("a" * (MAX_COMMAND_CHARS + 1)) is None


@pytest.mark.parametrize("command,expected", [
    ("ca't' x", [["cat", "x"]]),
    ("@'C:/a b/c'", [["@C:/a b/c"]]),
    ("curl @'C:/a b/c'", [["curl", "@C:/a b/c"]]),
    ("echo '$(id)'", [["echo", "$(id)"]]),
    ('echo "a b"', [["echo", "a b"]]),
    ("echo 'a'\"b\"c", [["echo", "abc"]]),
    ("echo ''", [["echo", ""]]),
    ('echo ""x', [["echo", "x"]]),
    ("echo 'a  b'   c", [["echo", "a  b", "c"]]),
    ("  echo hi  ", [["echo", "hi"]]),
    ("a_b.c/d:e@f=g,h+i-j", [["a_b.c/d:e@f=g,h+i-j"]]),
    ("echo '\\n'", [["echo", "\\n"]]),
    ("echo 'it\"s'", [["echo", 'it"s']]),
    ('echo "it\'s"', [["echo", "it's"]]),
])
def test_words_are_the_final_unquoted_words(command, expected):
    assert words_of(command) == expected


def test_operators_separate_segments_with_or_without_spaces():
    assert parse("a;b&&c||d|e") == [Segment(("a",), False), Segment(("b",), False), Segment(("c",), False),
                                    Segment(("d",), False), Segment(("e",), True)]
    assert parse("a ; b && c || d | e") == parse("a;b&&c||d|e")


def test_quoted_operators_and_redirects_are_plain_words():
    assert words_of("echo ';' '&&' '|' '2>&1'") == [["echo", ";", "&&", "|", "2>&1"]]


def test_a_single_trailing_semicolon_is_allowed():
    assert parse("a;") == [Segment(("a",), False)]
    assert parse("a ; ") == [Segment(("a",), False)]
    assert parse("a 2>&1;") == [Segment(("a",), False)]


@pytest.mark.parametrize("redirect", ["2>&1", "2>/dev/null", ">/dev/null", "1>/dev/null", "&>/dev/null"])
def test_each_redirect_is_dropped_from_the_words(redirect):
    assert parse(f"a {redirect} b") == [Segment(("a", "b"), False)]
    assert parse(f"{redirect} a") == [Segment(("a",), False)]
    assert parse(f"a {redirect}; b") == [Segment(("a",), False), Segment(("b",), False)]
    assert parse(f"a {redirect}| b") == [Segment(("a",), False), Segment(("b",), True)]
    assert parse(f"a {redirect}&& b") == [Segment(("a",), False), Segment(("b",), False)]


@pytest.mark.parametrize("command", [
    "a2>&1", "a 2>&1x", "a 2>&1'x'", 'a 2>/dev/null"x"', "a 2>/dev/nullx", "a >/dev/null/x", "x>/dev/null",
    "'x'>/dev/null", "a&>/dev/null", "a 2>&1&>/dev/null", "a 2>&2", "a 3>&1", "a 12>&1", "a >&1", "a >/tmp/x",
    "a 2>/tmp/x", "a 1>x", "a &>x", "a >>/dev/null", "a 2>>/dev/null", "a 2>&1 &", "a 2>/dev/null&",
])
def test_a_redirect_counts_only_as_a_whole_token_standing_alone(command):
    assert parse(command) is None


@pytest.mark.parametrize("command", ["2>&1", ">/dev/null", "a; 2>&1", "a | 2>&1", "a && >/dev/null", "2>&1 ; a", "a; 2>&1;"])
def test_a_segment_holding_only_a_redirect_is_empty(command):
    assert parse(command) is None


def test_the_redirect_and_pipe_forms_a_real_model_used():
    assert parse("a 2>&1 | b") == [Segment(("a",), False), Segment(("b",), True)]
    assert parse("ls x 2>/dev/null; echo '---'; ls y") == [
        Segment(("ls", "x"), False), Segment(("echo", "---"), False), Segment(("ls", "y"), False)]


@pytest.mark.parametrize("text", [
    "ca't' x", "@'C:/a b/c'", "'$(id)'", "'a'\"b\"c", "''", '""x', "'a  b'   c", "a_b.c/d:e@f=g,h+i-j", "'\\n'",
    "'it\"s'", '"it\'s"', "-x --y", "'*' '?' '[a]' '{a,b}' '~'", "1 2 3", "a=b",
    '"\\n"', '"\\t"', '"\\r"', '"a\\tb"', '"\\n%{http_code}\\n"', '"\\n"\'x\'y',
])
def test_the_words_match_what_real_bash_hands_a_program(text):
    command = f"printf '[%s]\\n' {text}"
    done = run_in_bash(command)
    assert done.returncode == 0
    assert done.stdout.splitlines() == [f"[{word}]" for word in parse(command)[0].words[2:]]


STATUS_TEXTS = ["$?", '"$?"', '"EXIT:$?"', '"---EXIT:$?---"', "a$?b", 'a"$?"b', '"$?$?"', "$?$?", '"$??"', 'x $? "y z"']


@pytest.mark.parametrize("text", STATUS_TEXTS)
def test_the_exit_status_keeps_its_two_characters_and_marks_the_segment(text):
    segment = parse(f"echo {text}")[0]
    assert "$?" in " ".join(segment.words) and segment.uses_status


@pytest.mark.parametrize("text", STATUS_TEXTS)
def test_real_bash_changes_only_the_exit_status_in_the_words(text):
    command = f"printf '[%s]\\n' {text}"
    done = run_in_bash(f"(exit 7); {command}")
    expected = [word.replace("$?", "7") for word in parse(command)[0].words[2:]]
    assert done.stdout.splitlines() == [f"[{word}]" for word in expected]


def test_uses_status_marks_only_the_segment_that_holds_it():
    assert [segment.uses_status for segment in parse('curl x; echo "$?"; ls y | wc -l')] == [False, True, False, False]
    assert Segment(("a",), False).uses_status is False


def test_a_single_quoted_exit_status_is_literal_and_still_marks_the_segment():
    command = "printf '[%s]\\n' '$?'"
    assert parse(command)[0].words[2:] == ("$?",) and parse(command)[0].uses_status
    assert run_in_bash(f"(exit 7); {command}").stdout.splitlines() == ["[$?]"]


@pytest.mark.parametrize("command", [
    'echo "$HOME"', 'echo "$1"', 'echo "$$"', 'echo "$(id)"', 'echo "${?}"', 'echo "$"', 'echo "$?$"', 'echo "$?$HOME"',
    "echo $HOME", "echo $1", "echo $$", "echo $(id)", "echo ${?}", "echo $", "echo $?$", "echo $?$HOME", "echo $??",
    "echo $?*", "echo $?(", "echo $'?'", 'echo $"?"', 'echo "$"?', 'echo "$" ?', "echo '$'?", "echo $ ?",
])
def test_every_other_dollar_is_refused(command):
    assert parse(command) is None


def test_a_doubled_backslash_is_outside_the_grammar():
    assert parse("printf '[%s]\\n' 'a\\\\b' c") is None
    assert parse("echo 'a\\b'")[0].words == ("echo", "a\\b")


@pytest.mark.parametrize("command,word", [
    ('echo "\\n"', "\\n"), ('echo "\\t"', "\\t"), ('echo "\\r"', "\\r"), ('echo "a\\nb\\tc"', "a\\nb\\tc"),
    ('echo "\\n%{http_code}\\n"', "\\n%{http_code}\\n"),
])
def test_a_backslash_before_n_t_or_r_keeps_both_characters(command, word):
    assert words_of(command) == [["echo", word]]


@pytest.mark.parametrize("command", [
    'echo "a\\b"', 'echo "\\\\"', 'echo "a\\"', 'echo "\\', 'echo "\\n\\"', 'echo "\\\\n"', 'echo "\\$x"', 'echo "\\`x"',
    'echo "\\""', 'echo "\\a"', 'echo "\\N"', 'echo "\\ "', 'echo "\\!"',
])
def test_every_other_backslash_in_double_quotes_is_refused(command):
    assert parse(command) is None


def test_real_bash_shows_why_the_other_backslashes_stay_refused():
    changes_the_word = "printf '[%s]\\n' \"\\\\\""
    assert run_in_bash(changes_the_word).stdout.splitlines() == ["[\\]"]
    assert parse(changes_the_word) is None
    hides_the_quote = "printf '[%s]\\n' \"a\\\""
    assert run_in_bash(hides_the_quote).returncode != 0
    assert parse(hides_the_quote) is None
    outside_the_named_three = "printf '[%s]\\n' \"a\\b\""
    assert run_in_bash(outside_the_named_three).stdout.splitlines() == ["[a\\b]"]
    assert parse(outside_the_named_three) is None
