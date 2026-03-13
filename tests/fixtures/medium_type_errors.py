# Medium — Type Checking Issues
# Expected: TYPE001, TYPE002, TYPE003, TYPE005, TYPE007

from typing import Optional


def no_annotation(x):
    return x * 2


def broken_math(a: int, b: int) -> int:
    result = a + b


def greet(name: str = 42) -> str:
    return f"Hello, {name}"


def set_count(count: int = "many") -> None:
    print(count)


def format_name(name: Optional[str]) -> str:
    return name.upper()


def safe_format(name: Optional[str]) -> str:
    if name is not None:
        return name.upper()
    return "anonymous"


def collect_items(items: list = []) -> list:
    items.append(1)
    return items


def build_config(settings: dict = {}) -> dict:
    settings["default"] = True
    return settings
