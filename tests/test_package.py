import subprocess
import sys

import ida_colors


def test_all_names_exist() -> None:
    missing = [name for name in ida_colors.__all__ if not hasattr(ida_colors, name)]
    assert missing == []


def test_import_does_not_pull_in_idapro() -> None:
    # Run in a subprocess, since this test session may already have imported idapro.
    subprocess.run([sys.executable, '-c', 'import ida_colors, sys; assert "idapro" not in sys.modules'], check=True)
