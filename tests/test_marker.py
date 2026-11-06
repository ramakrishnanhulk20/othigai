"""Shows the marker reaches a model whole through the two ways a child can read the key file.

Does not cover: a home with extra patterns added through register_redaction_patterns, or a
terminal backend other than the local one.
"""

import json
import secrets
import subprocess

import hermes_rig

KEY_BODY = "Bright Ledger vendor portal\nuser: accounts@brightledger.example\naccess code: {marker}\n"

REDACTOR_CHECK = """
import json, sys
from agent.redact import redact_sensitive_text, redact_terminal_output
damaged = 0
for line in sys.stdin:
    marker, body = json.loads(line)
    rendered = "\\n".join(f"{n}|{text}" for n, text in enumerate(body.splitlines(), 1))
    seen_by_read = redact_sensitive_text(rendered, file_read=True)
    seen_by_shell = redact_terminal_output(body, "cat portal-login.txt")
    damaged += marker not in seen_by_read or marker not in seen_by_shell
print(damaged)
"""


def test_marker_shape_survives_both_masking_paths_in_hermes_code(rig):
    markers = [secrets.token_hex(16) for _ in range(500)]
    feed = "\n".join(json.dumps([m, KEY_BODY.format(marker=m)]) for m in markers)
    done = subprocess.run(
        [hermes_rig.hermes_env_python(rig.home), "-c", REDACTOR_CHECK], input=feed, capture_output=True,
        text=True, encoding="utf-8", env=hermes_rig.clean_env(rig.home), timeout=120)
    assert done.returncode == 0, done.stderr[-800:]
    assert done.stdout.strip() == "0"


def test_model_receives_marker_whole_through_read_file_and_terminal(rig, tmp_path):
    marker = secrets.token_hex(16)
    key_file = tmp_path / "portal-login.txt"
    key_file.write_text(KEY_BODY.format(marker=marker), encoding="utf-8")
    path = key_file.as_posix()
    rig.set_script({"parent_calls": [
        {"name": "read_file", "arguments": {"path": path}},
        {"name": "terminal", "arguments": {"command": f"cat {path}"}}]})
    done = rig.chat("Please check the saved login file.")
    assert done.returncode == 0, done.stderr[-800:]
    last_request = rig.requests("parent")[-1]["body"]["messages"]
    results = [str(m.get("content")) for m in last_request if m.get("role") == "tool"]
    assert len(results) == 2
    assert all(marker in result for result in results), results
