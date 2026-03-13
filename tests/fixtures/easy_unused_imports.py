# Easy — Unused Imports
# Expected: DEAD004 (3 unused modules)

import collections
import json
import os
from pathlib import Path
import re
import sys

cwd = os.getcwd()
version = sys.version
home = Path.home()
