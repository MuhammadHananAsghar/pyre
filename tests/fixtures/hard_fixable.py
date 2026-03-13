# Hard — Fixable Issues (tests the `ignyt fix` engine)
# After running `ignyt fix`, this file should be automatically cleaned up.
#
# Expected auto-fixes:
#   DEAD004 — Remove unused imports (json, collections)
#   SEC005  — yaml.load → yaml.safe_load
#   FMT001  — Sort imports alphabetically

import sys
import os
import collections
import json
import yaml
from pathlib import Path

# Only os, sys, yaml, and Path are used.
cwd = os.getcwd()
version = sys.version
home = Path.home()


def load_data(raw: str) -> dict:
    # SEC005: should be auto-fixed to yaml.safe_load
    return yaml.load(raw)


def load_more(raw: str) -> dict:
    # This one is already safe — should NOT be touched
    return yaml.safe_load(raw)
