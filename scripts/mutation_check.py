"""Verify that fixtures detect predicate and individual selection-list value removals."""

import copy
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from evaluate import load_rule, run


def check(rule, manifest, root):
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
    rule = load_rule(root / manifest["rule"])

    result, output = check(rule, manifest, root)
    if result != 0:
        print("FAIL: original rule must pass before mutation testing")
        print(output)
        return 1

    print("PASS: original rule passes all fixture expectations")

    predicates = list(rule["detection"]["selection"])
    if len(predicates) < 2:
        raise ValueError(
            "Predicate-removal checks require at least two predicates"
        )

    totals = {"predicate": 0, "value": 0}
    detected = dict(totals)
    errors = 0
    selection = rule["detection"]["selection"]
    for predicate, values in selection.items():
        mutations = [("predicate", None)]
        if isinstance(values, list) and len(values) > 1:
            mutations.extend(("value", i) for i in range(len(values)))
        for kind, index in mutations:
            mutated = copy.deepcopy(rule)
            target = mutated["detection"]["selection"]
            label = predicate
            if kind == "predicate":
                del target[predicate]
            else:
                label += f" value {target[predicate].pop(index)!r}"
            totals[kind] += 1
            try:
                result, output = check(mutated, manifest, root)
            except Exception as exc:
                errors += 1
                print(f"ERROR: invalid {kind} mutation {label}: {exc}")
                continue
            if result == 1:
                detected[kind] += 1
                print(f"PASS: tests caught removal of {label}")
            else:
                print(f"FAIL: tests did not catch removal of {label}")
                print(output)

    for kind in totals:
        print(f"{detected[kind]}/{totals[kind]} {kind} mutations detected")
    print("Original YAML file unchanged")
    if errors:
        return 2
    return 0 if detected == totals else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
