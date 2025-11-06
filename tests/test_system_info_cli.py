import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "blncs" / "utils" / "system_info.py"


@pytest.mark.skipif(sys.platform == "win32", reason="CLI test relies on POSIX-style invocations under WSL")
def test_system_info_json_output():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--json"],
        check=True,
        capture_output=True,
        text=True,
    )

    data = json.loads(result.stdout)
    assert "system" in data
    assert "memory" in data
    assert isinstance(data["system"], dict)
