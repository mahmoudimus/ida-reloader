"""
Setup script for ida-reloader.

This file exists for backwards compatibility with older tools.
Modern installations should use pyproject.toml.
"""
from setuptools import setup, find_packages
import sys
from pathlib import Path

# Get version from ida_reloader module
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))
from ida_reloader import __version__

setup(
    name="ida-reloader",
    version=__version__,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)
