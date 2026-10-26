"""Parsing check only: no fixture evaluation and no conversion."""
import sys
from pathlib import Path
from sigma.collection import SigmaCollection

collection = SigmaCollection.from_yaml(Path(sys.argv[1]).read_text())
if len(collection.rules) != 1:
    raise ValueError("Expected exactly one rule")
print("PASS: pySigma parsed 1 rule (no fixture evaluation or SPL execution)")
