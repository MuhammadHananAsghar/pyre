# Medium — Dead Code Detection
# Expected: DEAD001, DEAD002, DEAD003, DEAD004, DEAD005, DEAD006

import json
import os


class _OldCache:
    """Private class never referenced anywhere."""

    def get(self) -> None:
        pass


def _helper():
    """This private function is never called."""
    return 42


def _used_helper():
    """This one IS called."""
    return "ok"


def process() -> str:
    result = _used_helper()
    return result


def early_return(x: int) -> int:
    if x > 0:
        return x
        y = x + 1
    return 0


def compute(a: int, b: int) -> int:
    unused_var = a * b
    return a + b


def transform(data: list, options: dict) -> list:
    return [item * 2 for item in data]


cwd = os.getcwd()
