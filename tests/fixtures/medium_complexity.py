# Medium — Complexity Issues
# Expected diagnostics:
#   CMPLX001 (high cyclomatic complexity)
#   CMPLX003 (too many arguments)
#   CMPLX006 (too deeply nested)

def simple_function(x: int) -> int:
    """Low complexity — should NOT be flagged."""
    if x > 0:
        return x
    return -x


def overly_complex(a: int, b: int, c: int) -> str:
    """High cyclomatic complexity from many branches."""
    if a > 10:
        if b > 5:
            if c > 0:
                return "deep_positive"
            elif c == 0:
                return "deep_zero"
            else:
                return "deep_negative"
        elif b == 0:
            return "mid_zero"
        else:
            return "mid_else"
    elif a > 5:
        if b > 0:
            return "medium"
        else:
            return "medium_else"
    elif a > 0:
        return "low"
    else:
        return "negative"


def too_many_params(a: int, b: int, c: int, d: int, e: int, f: int, g: int) -> int:
    """CMPLX003: too many arguments (7 > default 5)."""
    return a + b + c + d + e + f + g


def deeply_nested(data: list) -> str:
    """CMPLX006: excessive nesting depth."""
    for item in data:
        if isinstance(item, dict):
            for key in item:
                if key.startswith("_"):
                    for sub in item[key]:
                        if sub > 0:
                            return "found"
    return "not found"
