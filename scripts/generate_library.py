#!/usr/bin/env python3
"""Generate the Acme rules library from the prebuilt rules in detection-rules-library.

Each prebuilt rule becomes one Acme rule per (business unit, environment) variant, until the
library holds --count rules. The output is deterministic: rerunning it with the same source
ref writes the same files, with the same rule ids. See README.md.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import uuid
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

ACME_NAMESPACE = uuid.UUID("6f1c3a52-6a8e-4d3e-9a59-ac3e0b1e5000")
LIBRARY_DIR = "rules"
BUSINESS_UNITS: Tuple[Tuple[str, str], ...] = (
    ("corporate", "Corporate IT"),
    ("retail", "Retail"),
    ("manufacturing", "Manufacturing"),
    ("logistics", "Logistics"),
    ("finance", "Finance"),
    ("research", "Research"),
    ("healthcare", "Healthcare"),
    ("media", "Media"),
)
ENVIRONMENTS: Tuple[Tuple[str, str], ...] = (
    ("prod", "Production"),
    ("staging", "Staging"),
    ("dev", "Development"),
)
SEVERITY_DOWN = {"critical": ("high", 73), "high": ("medium", 47), "medium": ("low", 21), "low": ("low", 21)}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


def read_base_rules(source: Path, ref: str) -> List[Tuple[str, dict]]:
    """Prebuilt rules at the ref, keyed by their folder under rules/, without deprecated stubs."""
    paths = [
        path
        for path in git(source, "ls-tree", "-r", "--name-only", ref, "--", LIBRARY_DIR).split("\n")
        if path.endswith(".json") and "/_" not in path
    ]
    batch = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=source,
        input="".join(f"{ref}:{path}\n" for path in paths).encode(),
        capture_output=True,
        check=True,
    ).stdout
    rules: List[Tuple[str, dict]] = []
    offset = 0
    for path in paths:
        header_end = batch.index(b"\n", offset)
        size = int(batch[offset:header_end].split()[2])
        body = batch[header_end + 1 : header_end + 1 + size]
        offset = header_end + 1 + size + 1
        rule = json.loads(body)
        if not rule["attributes"].get("deprecated"):
            rules.append((path[len(LIBRARY_DIR) + 1 :], rule))
    return sorted(rules, key=lambda item: item[0])


def acme_index(pattern: str, unit: str, env: str) -> str:
    return f"acme-{unit}-{env}-{pattern}"


def skip_leading_comments(query: str) -> int:
    position = 0
    while True:
        match = re.match(r"\s*(//[^\n]*\n|/\*.*?\*/)", query[position:], re.DOTALL)
        if not match:
            return position
        position += match.end()


def rewrite_esql_sources(query: str, unit: str, env: str) -> Tuple[str, bool]:
    start = skip_leading_comments(query)
    match = re.compile(r"(\s*from\s+)(.+?)(?=\s+metadata\b|\s*\||\s*$)", re.IGNORECASE | re.DOTALL).match(query, start)
    if not match:
        return query, False
    sources = ", ".join(acme_index(source.strip(), unit, env) for source in match.group(2).split(",") if source.strip())
    return query[: match.start(2)] + sources + query[match.end(2) :], True


def make_variant(base: dict, unit: Tuple[str, str], env: Tuple[str, str]) -> Tuple[dict, bool]:
    attributes = json.loads(json.dumps(base["attributes"]))
    unit_id, unit_name = unit
    env_id, env_name = env
    rule_id = str(uuid.uuid5(ACME_NAMESPACE, f"{attributes['rule_id']}:{unit_id}:{env_id}"))
    esql_rewritten = True

    attributes["rule_id"] = rule_id
    attributes["version"] = 1
    attributes["author"] = ["Acme Security Engineering"]
    attributes["name"] = f"Acme {unit_name} ({env_name}): {attributes['name']}"
    attributes["description"] = f"{attributes['description'].rstrip()} Tuned for the Acme {unit_name} {env_name.lower()} environment."
    attributes["tags"] = [
        *attributes.get("tags", []),
        f"Acme Business Unit: {unit_name}",
        f"Acme Environment: {env_name}",
        "Source: Acme Rules Library",
    ]
    if "index" in attributes:
        attributes["index"] = [acme_index(pattern, unit_id, env_id) for pattern in attributes["index"]]
    if "threat_index" in attributes:
        attributes["threat_index"] = [acme_index(pattern, unit_id, env_id) for pattern in attributes["threat_index"]]
    if attributes["type"] == "esql":
        attributes["query"], esql_rewritten = rewrite_esql_sources(attributes["query"], unit_id, env_id)
    if env_id == "dev":
        attributes["severity"], attributes["risk_score"] = SEVERITY_DOWN[attributes["severity"]]
        attributes.pop("severity_mapping", None)
        attributes.pop("risk_score_mapping", None)

    return {"attributes": attributes, "id": f"{rule_id}_1", "type": "security-rule"}, esql_rewritten


def variant_of(variant: int, base_index: int) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    # Rotating by base keeps a partly filled environment spread across business units.
    unit = BUSINESS_UNITS[(variant + base_index) % len(BUSINESS_UNITS)]
    env = ENVIRONMENTS[variant // len(BUSINESS_UNITS)]
    return unit, env


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=root.parent / "detection-rules-library")
    parser.add_argument("--ref", default="main/v9.6.1")
    parser.add_argument("--count", type=int, default=40_000)
    parser.add_argument("--apply", action="store_true", help="write rules/ (without it, only print the summary)")
    args = parser.parse_args()

    bases = read_base_rules(args.source, args.ref)
    max_count = len(bases) * len(BUSINESS_UNITS) * len(ENVIRONMENTS)
    if args.count > max_count:
        raise SystemExit(f"--count {args.count} is more than the {max_count} variants available")

    outputs: Dict[str, dict] = {}
    by_folder: Counter = Counter()
    by_type: Counter = Counter()
    esql_unchanged = 0
    for position in range(args.count):
        base_index = position % len(bases)
        relative, base = bases[base_index]
        unit, env = variant_of(position // len(bases), base_index)
        rule, esql_rewritten = make_variant(base, unit, env)
        folder, name = relative.rsplit("/", 1)
        path = f"{LIBRARY_DIR}/{unit[0]}/{folder}/{name[: -len('.json')]}_{env[0]}.json"
        if path in outputs:
            raise SystemExit(f"Duplicate path {path}")
        outputs[path] = rule
        by_folder[path.rsplit("/", 1)[0]] += 1
        by_type[rule["attributes"]["type"]] += 1
        esql_unchanged += not esql_rewritten

    rule_ids = {rule["attributes"]["rule_id"] for rule in outputs.values()}
    names = {rule["attributes"]["name"] for rule in outputs.values()}
    print(f"Source: {args.source} @ {args.ref}, {len(bases)} prebuilt rules")
    print(f"Rules: {len(outputs)}, unique rule ids: {len(rule_ids)}, unique names: {len(names)}")
    print(f"By type: {dict(by_type.most_common())}")
    print(f"ES|QL queries without a FROM to rewrite: {esql_unchanged}")
    print(f"Folders: {len(by_folder)}, largest: {by_folder.most_common(3)}")
    by_unit = Counter(path.split("/")[1] for path in outputs)
    print(f"By business unit: {dict(sorted(by_unit.items()))}")
    if len(rule_ids) != len(outputs) or len(names) != len(outputs):
        raise SystemExit("Rule ids or names are not unique")
    if not args.apply:
        print("Dry run: nothing written. Pass --apply to write rules/.")
        return

    library = root / LIBRARY_DIR
    for child in library.iterdir() if library.exists() else []:
        if child.is_dir():
            shutil.rmtree(child)
    for path, rule in outputs.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(rule, indent=4, sort_keys=True))
    print(f"Wrote {len(outputs)} files under {library}")


if __name__ == "__main__":
    main()
