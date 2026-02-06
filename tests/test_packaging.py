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

    # Helper to check if a relative path exists in the tarball
    def has_file(pattern: str) -> bool:
        return any(pattern in f for f in filenames)

    # Mandatory inclusions
    assert has_file("src/coreason_identity/__init__.py"), "Source code missing from sdist"
    assert has_file("src/coreason_identity/utils/logger.py"), "Nested source code missing from sdist"
    assert has_file("pyproject.toml"), "pyproject.toml missing from sdist"
    assert has_file("README.md"), "README.md missing from sdist"
    assert has_file("LICENSE"), "LICENSE missing from sdist"
    assert has_file("NOTICE"), "NOTICE file missing from sdist"

    # Mandatory exclusions
    # Dev/Infra files
    excluded_patterns = [
        "/AGENTS.md",
        "/Dockerfile",
        "/mkdocs.yml",
        "/codecov.yml",
        "/.pre-commit-config.yaml",
        "/.github",
        "/tests/",
        "/docs/",
    ]

    for pattern in excluded_patterns:
        assert not has_file(pattern), f"{pattern} should be excluded from sdist"
        assert not any(f.endswith(pattern.lstrip("/")) for f in filenames), f"{pattern} should be excluded from sdist"


def test_wheel_contents(build_artifacts: Path) -> None:
    """
    Verifies the contents of the Wheel (whl).
    """
    wheel_files = list(build_artifacts.glob("*.whl"))
    assert len(wheel_files) == 1, "Expected exactly one wheel (.whl) file"
    wheel_path = wheel_files[0]

    with zipfile.ZipFile(wheel_path, "r") as z:
        filenames = z.namelist()

        # Check Metadata
        dist_info = [f for f in filenames if f.endswith(".dist-info/METADATA")]
        assert len(dist_info) == 1, "Could not find METADATA file in wheel"
        metadata = z.read(dist_info[0]).decode("utf-8")

        # Poetry/Packaging might use underscore or hyphen. Match the pyproject.toml name.
        assert "Name: coreason_identity" in metadata, "Incorrect Name in METADATA"
        assert "Version: 0.6.0" in metadata, "Incorrect Version in METADATA"

    # Mandatory inclusions
    assert "coreason_identity/__init__.py" in filenames, "Package root missing in wheel"
    assert "coreason_identity/utils/logger.py" in filenames, "Nested source missing in wheel"

    # Check that NOTICE is in the dist-info directory (standard for wheels)
    # or at the root? Usually standard licenses go to dist-info.
    # Poetry puts them in dist-info.
    assert any(f.endswith(".dist-info/NOTICE") for f in filenames) or "NOTICE" in filenames, "NOTICE missing from wheel"

    # Exclusions
    excluded_files = [
        "AGENTS.md",
        "Dockerfile",
        "mkdocs.yml",
        "codecov.yml",
        ".pre-commit-config.yaml",
    ]

    for f in excluded_files:
        assert f not in filenames, f"{f} should be excluded from wheel"

    assert not any(f.startswith("tests/") for f in filenames), "tests/ should be excluded from wheel"
    assert not any(f.startswith("docs/") for f in filenames), "docs/ should be excluded from wheel"
