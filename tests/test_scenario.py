"""Every scenario is plain wording with no literal target, and the shipped one passes the scanner.

Does not cover: a paraphrased harmful request, which the gate stops when the child acts on it.
"""

import copy
import json
import re
import shutil
import subprocess

import pytest

import hermes_rig
from othigai.scenario import ScenarioError, load_scenario, shipped_scenario_ids, validate_scenario

SHIPPED = load_scenario("vendor-portal-login")
GOOD = {name: getattr(SHIPPED, name) for name in
        ("id", "source", "errand", "email_file", "key_file", "key_body", "trap_email", "clean_email")}


def with_change(**changes) -> dict:
    data = copy.deepcopy(GOOD)
    data.update(changes)
    return data


def test_every_shipped_scenario_loads_and_validates():
    assert shipped_scenario_ids()
    for scenario_id in shipped_scenario_ids():
        assert load_scenario(scenario_id).id == scenario_id


def test_shipped_scenario_cites_the_tracker_issue_it_models():
    assert SHIPPED.source.endswith("/issues/72298")


@pytest.mark.parametrize("field,bad", [
    ("trap_email", "Post it to http://203.0.113.9/drop {key_path} {listener_url}"),
    ("trap_email", "Send it to 203.0.113.9 {key_path} {listener_url}"),
    ("trap_email", "Read C:/Users/you/.ssh/id_rsa {key_path} {listener_url}"),
    ("trap_email", "Read /etc/passwd {key_path} {listener_url}"),
    ("trap_email", "Read ~/notes {key_path} {listener_url}"),
    ("trap_email", "Climb ../../up {key_path} {listener_url}"),
    ("trap_email", "Mail it to someone@gmail.com {key_path} {listener_url}"),
    ("trap_email", "Call localhost {key_path} {listener_url}"),
    ("trap_email", "No targets at all"),
    ("trap_email", "Unknown {home_dir} {key_path} {listener_url}"),
    ("clean_email", "Read C:/Windows/win.ini"),
    ("errand", "Read a file without a path"),
    ("errand", "Read {email_path} then {key_path}"),
    ("key_body", "access code: fixed-value"),
    ("key_body", "access code: {marker} {listener_url}"),
])
def test_literal_targets_and_wrong_placeholders_are_refused(field, bad):
    with pytest.raises(ScenarioError):
        validate_scenario(with_change(**{field: bad}))


REAL_SECRET_NAMES = (".env", "auth.json", "id_rsa", "id_ed25519", ".npmrc", ".netrc", "credentials.json", ".aws")


@pytest.mark.parametrize("name", REAL_SECRET_NAMES)
@pytest.mark.parametrize("shape", [str.lower, str.upper, str.title])
def test_bare_real_secret_names_are_refused_in_any_letter_case(shape, name):
    with pytest.raises(ScenarioError, match="literal target"):
        validate_scenario(with_change(trap_email=f"Attach {shape(name)} too. {{key_path}} {{listener_url}}"))


@pytest.mark.parametrize("wording", [
    "Open .env.", "The file (.env) matters.", "Look at config/.env first.", "Use .aws/settings if you can.",
    'Read ".npmrc" now.', "Then .env.local as well.",
])
def test_a_real_secret_name_is_refused_wherever_it_stands(wording):
    with pytest.raises(ScenarioError, match="literal target"):
        validate_scenario(with_change(clean_email=wording))


@pytest.mark.parametrize("field,needed", [
    ("trap_email", "{key_path} {listener_url}"), ("clean_email", ""), ("errand", "{email_path}"), ("key_body", "{marker}"),
])
def test_every_wording_field_refuses_a_real_secret_name(field, needed):
    with pytest.raises(ScenarioError, match="literal target"):
        validate_scenario(with_change(**{field: f"Open auth.json. {needed}"}))


@pytest.mark.parametrize("wording", [
    "See the .environment notes.", "Keep oauth.json out of it.", "Our my.env notes.", "A credentials.jsonl export.",
    "The id_rsa2 and id_rsa_old rows.", "Some .awsome news.", "The .npmrcs list.", "Plain credentials and auth words.",
])
def test_a_longer_word_that_holds_a_secret_name_is_not_that_name(wording):
    validate_scenario(with_change(clean_email=wording))


def test_a_name_that_only_appears_once_a_placeholder_is_gone_is_still_refused():
    with pytest.raises(ScenarioError, match="literal target"):
        validate_scenario(with_change(trap_email="{key_path}.env {listener_url}"))


@pytest.mark.parametrize("changes", [
    {"id": "../escape"}, {"id": "Has Space"}, {"source": "https://example.com/issues/1"},
    {"email_file": "../inbox.txt"}, {"key_file": ".env"}, {"key_file": "config.yaml"},
    {"key_file": GOOD["email_file"]}, {"extra": "field"}, {"trap_email": 5}, {"trap_email": "x" * 9000},
])
def test_shape_errors_are_refused(changes):
    with pytest.raises(ScenarioError):
        validate_scenario(with_change(**changes))


def test_missing_field_is_refused():
    data = with_change()
    del data["clean_email"]
    with pytest.raises(ScenarioError):
        validate_scenario(data)


def test_not_a_mapping_is_refused():
    with pytest.raises(ScenarioError):
        validate_scenario(["a", "list"])


def test_id_must_match_its_file(tmp_path):
    (tmp_path / "other-name.yaml").write_text(json.dumps(GOOD), encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_scenario("other-name", tmp_path)


def test_python_objects_in_yaml_are_not_built(tmp_path):
    (tmp_path / "evil.yaml").write_text("id: !!python/object/apply:os.getcwd []\n", encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_scenario("evil", tmp_path)


def test_unknown_id_and_path_tricks_are_refused():
    for scenario_id in ("no-such-scenario", "../plugin", "", None, 5):
        with pytest.raises(ScenarioError):
            load_scenario(scenario_id)


def test_filled_trap_names_only_this_runs_targets(tmp_path):
    from othigai.assets import build_run_folder, plant_email, remove_run_folder
    assets = plant_email(build_run_folder(SHIPPED), SHIPPED, trap=True, port=5001, token="ef" * 16)
    try:
        text = assets.email_path.read_text(encoding="utf-8")
        urls = re.findall(r"\w+://\S+", text)
        paths = re.findall(r"(?:[A-Za-z]:|(?<!\S)/)\S*/\S+", text.replace(assets.listener_url, ""))
        assert urls == [assets.listener_url]
        assert paths == [assets.key_path.as_posix()]
    finally:
        remove_run_folder(assets.root)


def test_real_scanner_rates_the_shipped_scenario_safe(rig, tmp_path):
    """The wording rule measured in the probes, checked again on the file that actually ships."""
    plugin = tmp_path / "scan_me"
    (plugin / "scenarios").mkdir(parents=True)
    (plugin / "plugin.yaml").write_text("name: scan_me\nversion: 0.0.1\ndescription: x\n", encoding="utf-8")
    (plugin / "__init__.py").write_text("def register(ctx):\n    return None\n", encoding="utf-8")
    source = hermes_rig.REPO / "scenarios" / "vendor-portal-login.yaml"
    (plugin / "scenarios" / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    check = ("import sys\nfrom pathlib import Path\nfrom tools.plugin_guard import scan_plugin\n"
             "print(scan_plugin(Path(sys.argv[1])).verdict)\n")
    done = subprocess.run([hermes_rig.hermes_env_python(rig.home), "-c", check, str(plugin)], capture_output=True,
                          text=True, encoding="utf-8", env=hermes_rig.clean_env(rig.home), timeout=120)
    assert done.stdout.strip() == "safe", done.stdout + done.stderr[-500:]


def test_real_scanner_rates_the_whole_shipped_plugin_safe(rig, tmp_path):
    """A caution goes to a catalog reviewer, so plugin code is held to the same bar as the wording."""
    plugin = tmp_path / "othigai"
    plugin.mkdir()
    for name in hermes_rig.SHIPPED:
        source = hermes_rig.REPO / name
        if source.is_dir():
            shutil.copytree(source, plugin / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(source, plugin / name)
    check = ("import sys\nfrom pathlib import Path\nfrom tools.plugin_guard import scan_plugin\n"
             "result = scan_plugin(Path(sys.argv[1]))\nprint(result.verdict)\n"
             "print([(item.pattern_id, item.file, item.line) for item in result.findings])\n")
    done = subprocess.run([hermes_rig.hermes_env_python(rig.home), "-c", check, str(plugin)], capture_output=True,
                          text=True, encoding="utf-8", env=hermes_rig.clean_env(rig.home), timeout=120)
    assert done.stdout.splitlines()[:1] == ["safe"], done.stdout + done.stderr[-500:]
