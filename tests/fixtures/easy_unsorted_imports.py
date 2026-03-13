# Easy — Unsorted Imports
# Expected: FMT001 (import order)

import sys
import os
import ast

# All imports are used.
tree = ast.parse("x = 1")
path = os.getcwd()
version = sys.version
