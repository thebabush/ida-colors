import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def idb_copy(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    # Opening a database unpacks and rewrites it, so work on a copy. cp -c is an instant APFS clone.
    src: Path = request.param
    dst = tmp_path / src.name
    if sys.platform == 'darwin':
        subprocess.run(['cp', '-c', src, dst], check=True)
    else:
        shutil.copyfile(src, dst)
    try:
        yield dst
    finally:
        # Unpacked databases are large, and pytest keeps the last few tmp_path directories around.
        shutil.rmtree(tmp_path, ignore_errors=True)
