"""Runs real Hermes against the local stub for the end-to-end tests.

The home defaults to the probe home and must point at the stub, so no test can reach a real
model or a real install. The environment is an allow-list: a credential in the shell that
starts the tests cannot reach Hermes under a name nobody thought of.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

REPO = Path(__file__).resolve().parents[1]
STUB = Path(__file__).resolve().parent / "stub_model.py"
DEFAULT_HOME = REPO / "scratchpad" / "probes" / "home"
STUB_URL = "http://127.0.0.1:18080/v1"
SHIPPED = ("plugin.yaml", "__init__.py", "othigai", "scenarios")
ALLOWED_ENV = (
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP",
    "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "HOMEDRIVE", "HOMEPATH", "USERNAME", "USERDOMAIN", "COMPUTERNAME",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
)


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or DEFAULT_HOME).resolve()


def home_uses_stub(home: Path) -> bool:
    try:
        config = YAML(typ="safe", pure=True).load((home / "config.yaml").read_text(encoding="utf-8"))
    except (OSError, YAMLError):
        return False
    return str((config.get("model") or {}).get("base_url", "")).rstrip("/") == STUB_URL


def hermes_exe() -> str | None:
    found = shutil.which("hermes")
    if found:
        return found
    candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "bin" / "hermes.exe"
    return str(candidate) if candidate.exists() else None


def clean_env(home: Path) -> dict:
    env = {name: os.environ[name] for name in ALLOWED_ENV if name in os.environ}
    env.update({"HERMES_HOME": str(home).replace("\\", "/"), "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "TERM": "dumb"})
    return env


def hermes_env_python(home: Path) -> str:
    found = sorted((home / "installs").glob("*/environments/*/venv/Scripts/python.exe"))
    found += sorted((home / "installs").glob("*/environments/*/venv/bin/python"))
    if not found:
        raise FileNotFoundError("no Hermes environment Python under this home")
    return str(found[0])


def stub_is_up() -> bool:
    try:
        with urllib.request.urlopen(f"{STUB_URL}/models", timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


class Rig:
    """One Hermes home and one stub. A test sets the script, runs a turn, reads the log."""

    def __init__(self, home: Path, workdir: Path, scratch: Path):
        self.home, self.workdir, self.scratch = home, workdir, scratch
        self.script_path = scratch / "stub-script.json"
        self.log_path = scratch / "stub-requests.jsonl"
        self._stub: subprocess.Popen | None = None
        self.exe = hermes_exe()
        self.extra_env: dict = {}

    def set_script(self, script: dict) -> None:
        self.script_path.write_text(json.dumps(script), encoding="utf-8")
        self.log_path.write_text("", encoding="utf-8")

    def start_stub(self) -> None:
        if stub_is_up():
            raise RuntimeError("something already answers on the stub port, stop it first")
        self.set_script({})
        self._stub = subprocess.Popen(
            [sys.executable, str(STUB), "--script", str(self.script_path), "--log", str(self.log_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if stub_is_up():
                return
            time.sleep(0.1)
        self.stop_stub()
        raise RuntimeError("stub did not start")

    def stop_stub(self) -> None:
        if self._stub is not None:
            self._stub.terminate()
            self._stub.wait(timeout=20)
            self._stub = None

    def hermes(self, args: list[str], timeout: int = 240) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.exe, *args], cwd=self.workdir, env={**clean_env(self.home), **self.extra_env},
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            stdin=subprocess.DEVNULL)

    def chat(self, prompt: str, timeout: int = 240) -> subprocess.CompletedProcess:
        return self.hermes(["chat", "-q", prompt], timeout=timeout)

    def stop_gateway(self) -> None:
        self.hermes(["gateway", "stop"], timeout=120)

    def requests(self, lane: str | None = None) -> list[dict]:
        lines = [json.loads(x) for x in self.log_path.read_text(encoding="utf-8").splitlines() if x.strip()]
        return [x for x in lines if lane is None or x["lane"] == lane]

    def install_plugin(self) -> None:
        target = self.home / "plugins" / "othigai"
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        for name in SHIPPED:
            source = REPO / name
            if source.is_dir():
                shutil.copytree(source, target / name, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy2(source, target / name)
