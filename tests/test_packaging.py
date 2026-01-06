# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import shutil
import subprocess
import tarfile
import zipfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def build_artifacts() -> Generator[Path, None, None]:
    """
    Builds the project artifacts (sdist and wheel) and returns the path to the dist directory.
    Cleans up before and after.
    """
    root_dir = Path(__file__).parent.parent
    dist_dir = root_dir / "dist"

    # Clean up previous builds
    if dist_dir.exists():
        shutil.rmtree(dist_dir)

    # Run poetry build
    subprocess.run(["poetry", "build"], cwd=root_dir, check=True, capture_output=True)

    yield dist_dir

    # Cleanup is optional, but good for hygiene.
    # Leaving it for inspection if test fails can be useful, but automated tests should clean up.
    if dist_dir.exists():
        shutil.rmtree(dist_dir)


def test_sdist_contents(build_artifacts: Path) -> None:
    """
    Verifies the contents of the Source Distribution (sdist).
    """
    sdist_files = list(build_artifacts.glob("*.tar.gz"))
    assert len(sdist_files) == 1, "Expected exactly one sdist (.tar.gz) file"
    sdist_path = sdist_files[0]

    with tarfile.open(sdist_path, "r:gz") as tar:
        filenames = tar.getnames()

    # Normalize filenames (remove the top-level directory which is usually name-version/)
    # We just check if expected files exist inside that structure.
    # Example: coreason_identity-0.1.0/src/coreason_identity/__init__.py

    # Helper to check if a relative path exists in the tarball
    def has_file(pattern: str) -> bool:
        return any(pattern in f for f in filenames)

    # Mandatory inclusions
    assert has_file("src/coreason_identity/__init__.py"), "Source code missing from sdist"
    assert has_file("pyproject.toml"), "pyproject.toml missing from sdist"
    assert has_file("README.md"), "README.md missing from sdist"
    assert has_file("LICENSE"), "LICENSE missing from sdist"

    # Mandatory exclusions
    # Note: explicit checks for files that should NOT be there

    # AGENTS.md should be excluded
    assert not has_file("/AGENTS.md") and not any(f.endswith("AGENTS.md") for f in filenames), (
        "AGENTS.md should be excluded from sdist"
    )

    # Tests should be excluded
    # Note: filenames usually look like 'pkg-ver/tests/...' if included
    assert not any("/tests/" in f for f in filenames), "tests/ directory should be excluded from sdist"

    # Github workflows
    assert not any(".github" in f for f in filenames), ".github directory should be excluded from sdist"


def test_wheel_contents(build_artifacts: Path) -> None:
    """
    Verifies the contents of the Wheel (whl).
    """
    wheel_files = list(build_artifacts.glob("*.whl"))
    assert len(wheel_files) == 1, "Expected exactly one wheel (.whl) file"
    wheel_path = wheel_files[0]

    with zipfile.ZipFile(wheel_path, "r") as z:
        filenames = z.namelist()

    # Wheel layout is different: it puts src content at root (if configured right) or under package name.
    # With poetry src layout, it should be:
    # coreason_identity/__init__.py
    # coreason_identity-0.1.0.dist-info/...

    assert "coreason_identity/__init__.py" in filenames, "Package root missing in wheel"

    # Exclusions
    assert "AGENTS.md" not in filenames, "AGENTS.md should be excluded from wheel"
    assert not any(f.startswith("tests/") for f in filenames), "tests/ should be excluded from wheel"
