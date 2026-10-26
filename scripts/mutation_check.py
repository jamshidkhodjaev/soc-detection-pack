"""Verify that fixtures detect removal of parent and child predicates."""

import copy
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import yaml

from evaluate import run


def check(rule, manifest, root):
    # Capture fixture output so unexpected results can be shown clearly.
    output = io.StringIO()
    with redirect_stdout(output):
        result = run(rule, manifest, root)
    return result, output.getvalue()


def main():
    root = Path(__file__).resolve().parent.parent
    manifest_name = (
        sys.argv[1] if len(sys.argv) > 1 else "tests/iis_manifest.json"
    )
    manifest = json.loads((root / manifest_name).read_text())
    rule = yaml.safe_load((root / manifest["rule"]).read_text())

    result, output = check(rule, manifest, root)
    if result != 0:
        print("FAIL: original rule must pass before mutation testing")
        print(output)
        return 1

    print("PASS: original rule passes all fixture expectations")

    for predicate in ("ParentImage|endswith", "Image|endswith"):
        mutated = copy.deepcopy(rule)
        del mutated["detection"]["selection"][predicate]

        result, output = check(mutated, manifest, root)
        if result != 1:
            print(f"FAIL: tests did not catch removal of {predicate}")
            print(output)
            return 1

        print(f"PASS: tests caught removal of {predicate}")

    print("2/2 mutations detected; original YAML file unchanged")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)