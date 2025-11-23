"""
Setup script for ida-reloader.

This file exists for backwards compatibility with older tools.
Modern installations should use pyproject.toml.
"""
from setuptools import setup

# Read version from module
with open("ida_reloader.py") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break

setup(
    name="ida-reloader",
    version=version,
    py_modules=["ida_reloader"],
)
