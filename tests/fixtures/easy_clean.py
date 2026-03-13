# Easy — Clean Code (should produce ZERO diagnostics)
# Tests that Pyre does not false-positive on well-written Python.

import os
from pathlib import Path
import sys


def greet(name: str) -> str:
    """Return a greeting string."""
    return f"Hello, {name}!"


def add(a: int, b: int) -> int:
    """Simple addition."""
    return a + b


def read_config(path: Path) -> str:
    """Read a configuration file."""
    return path.read_text()


class User:
    """A simple user model."""

    def __init__(self, name: str, age: int) -> None:
        self.name = name
        self.age = age

    def display(self) -> str:
        return f"{self.name} ({self.age})"


# All imports are used
cwd = os.getcwd()
version = sys.version
home = Path.home()
