"""Tiny fail-closed evaluator for the documented endswith-only Sigma subset."""
import json
import sys
from datetime import datetime
from pathlib import Path


def compile_rule(rule):
    if not isinstance(rule, dict):
        raise ValueError("Expected one rule mapping")

    if rule.get("logsource") != {
        "category": "process_creation",
        "product": "windows",
    }:
        raise ValueError("Unsupported logsource")

    if any(key in rule for key in ("taxonomy", "correlation", "filter")):
        raise ValueError("Unsupported taxonomy, correlation or filter")

    detection = rule.get("detection", {})
    if (
        not isinstance(detection, dict)
        or set(detection) != {"selection", "condition"}
        or detection["condition"] != "selection"
    ):
        raise ValueError(
            "Only one selection and condition: selection are supported"
        )

    selection = detection["selection"]
    if not isinstance(selection, dict) or not selection:
        raise ValueError("Selection must be a nonempty mapping")

    predicates = []

    for key, value in selection.items():
        if not isinstance(key, str):
            raise ValueError("Selection keys must be strings")

        parts = key.split("|")
        field = parts[0]
        modifiers = tuple(parts[1:])

        if not field or modifiers not in (
            ("endswith",),
            ("contains",),
            ("contains", "all"),
        ):
            raise ValueError(f"Unsupported field/modifier: {key}")

        values = value if isinstance(value, list) else [value]
        if not values or any(
            not isinstance(v, str) or not v or "*" in v or "?" in v
            for v in values
        ):
            raise ValueError(
                "Only nonempty literal strings without wildcards are supported"
            )

        predicates.append(
            (
                field,
                modifiers[0],
                tuple(v.casefold() for v in values),
                modifiers == ("contains", "all"),
            )
        )

    return predicates


def matches(predicates, event):
    for key in ("product", "category", "EventID"):
        if key not in event:
            raise ValueError(f"Missing routing field: {key}")

    if type(event["EventID"]) is not int:
        raise ValueError("EventID must be an integer")

    if (
        event["product"],
        event["category"],
        event["EventID"],
    ) != ("windows", "process_creation", 1):
        return False

    outcomes = []

    for field, operation, values, require_all in predicates:
        value = event.get(field)

        if value is None:
            outcomes.append(False)
            continue

        if not isinstance(value, str):
            raise ValueError(f"Expected string for {field}")

        normalized = value.casefold()

        if operation == "endswith":
            outcomes.append(normalized.endswith(values))
        elif operation == "contains":
            found = [literal in normalized for literal in values]
            outcomes.append(all(found) if require_all else any(found))
        else:
            raise ValueError(f"Unsupported operation: {operation}")

    return all(outcomes)


def run(rule, manifest, root):
    predicates = compile_rule(rule)  # Validate all syntax before evaluating records.
    if not manifest["cases"]:
        raise ValueError("Empty test manifest")
    failed = 0
    for case in manifest["cases"]:
        if type(case["expected_match"]) is not bool:
            raise ValueError("expected_match must be boolean")
        lines = (root / case["fixture"]).read_text().splitlines()
        if len(lines) != 1:
            raise ValueError("This milestone requires exactly one JSONL record per fixture")
        event = json.loads(lines[0])
        if event.get("synthetic") is not True or event.get("event_id") != case["event_id"]:
            raise ValueError("Synthetic label or fixture ID is invalid")
        for field in ("timestamp_utc", "host", "CommandLine", "User"):
            if not isinstance(event.get(field), str) or not event[field]:
                raise ValueError(f"Missing/invalid fixture context: {field}")
        if not event["timestamp_utc"].endswith("Z"):
            raise ValueError("Timestamp must end in Z")
        datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00"))
        actual = matches(predicates, event)
        ok = actual == case["expected_match"]
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'} {event['event_id']}: expected={case['expected_match']} actual={actual}")
    print(f"{len(manifest['cases']) - failed}/{len(manifest['cases'])} fixture expectations passed")
    return 1 if failed else 0


def main():
    import yaml
    # Reject duplicate YAML keys rather than silently overwriting a predicate.
    class UniqueLoader(yaml.SafeLoader):
        pass
    def unique_mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in result:
                raise ValueError(f"Duplicate YAML key: {key}")
            result[key] = loader.construct_object(value_node)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    manifest_path = Path(sys.argv[1]).resolve()
    root = manifest_path.parent.parent
    manifest = json.loads(manifest_path.read_text())
    rule = yaml.load((root / manifest["rule"]).read_text(), Loader=UniqueLoader)
    return run(rule, manifest, root)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
