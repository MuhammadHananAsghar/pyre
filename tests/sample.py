import os
import sys
import json
from pathlib import Path

# Unused import above (json is never used)

def process_data(data):
    """This function has no return type annotation."""
    result = eval(data)  # SEC011: eval usage
    return result

def complex_handler(a, b, c, d, e, f, g):
    """Too many arguments."""
    if a:
        if b:
            if c:
                if d:
                    return "deep"
                else:
                    return "not so deep"
            else:
                return "medium"
        else:
            return "shallow"
    elif e:
        return "alternative"
    else:
        return "default"

x = os.getcwd()
p = Path(".")
y = sys.argv
