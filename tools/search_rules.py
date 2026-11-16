#!/usr/bin/env python3
"""Offline search CLI for the collected YARA-L rule corpus.

Examples:
  python3 tools/search_rules.py login --gcp
  python3 tools/search_rules.py IAM --content --license Apache-2.0
  python3 tools/search_rules.py service_account --repo GoogleCloudPlatform
  python3 tools/search_rules.py --stats
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULE_INDEX = ROOT / "catalog" / "RULE_INDEX.csv"
GCP_INDEX = ROOT / "catalog" / "GCP_RULE_INDEX.csv"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def rule_rows(gcp_only: bool) -> list[dict[str, str]]:
    rows = read_csv(GCP_INDEX if gcp_only else RULE_INDEX)
    if gcp_only:
        for row in rows:
            row["repository"] = row.get("source_repository", "")
            row["rule_name_or_item"] = row.get("rule_name", "")
            row["description"] = row.get("category", "")
            row["license"] = row.get("license", "")
            row["commit"] = row.get("source_commit", "")
    return rows


def content_for(row: dict[str, str]) -> str:
    path = ROOT / row.get("local_path", "")
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def searchable_text(row: dict[str, str], include_content: bool) -> str:
    fields = (
        row.get("local_path", ""),
        row.get("rule_name_or_item", ""),
        row.get("rule_name", ""),
        row.get("description", ""),
        row.get("repository", ""),
        row.get("source_repository", ""),
        row.get("license", ""),
        row.get("category", ""),
        row.get("collection", ""),
        row.get("upstream_file", ""),
    )
    text = "\n".join(fields)
    return text + ("\n" + content_for(row) if include_content else "")


def matches(row: dict[str, str], args: argparse.Namespace) -> bool:
    if args.license and args.license.lower() not in row.get("license", "").lower():
        return False
    repo = row.get("repository", row.get("source_repository", ""))
    if args.repo and args.repo.lower() not in repo.lower():
        return False
    if args.category:
        category = " ".join(
            [row.get("category", ""), row.get("collection", "")]
        ).lower()
        if args.category.lower() not in category:
            return False
    if args.regex:
        try:
            if not re.search(args.regex, searchable_text(row, args.content), re.I):
                return False
        except re.error as error:
            raise SystemExit(f"Invalid regex: {error}") from error
    elif args.terms:
        text = searchable_text(row, args.content).lower()
        checks = [term.lower() in text for term in args.terms]
        if not all(checks) if args.all_terms else not any(checks):
            return False
    return True


def public_result(row: dict[str, str], gcp_only: bool) -> dict[str, str]:
    result = {
        "local_path": row.get("local_path", ""),
        "rule_name": row.get("rule_name_or_item", row.get("rule_name", "")),
        "description": row.get("description", row.get("category", "")),
        "repository": row.get("repository", row.get("source_repository", "")),
        "commit": row.get("commit", row.get("source_commit", "")),
        "license": row.get("license", ""),
        "upstream_file": row.get("upstream_file", ""),
    }
    if gcp_only:
        result["syntax_validation_status"] = row.get("syntax_validation_status", "")
        result["udm_mapping_status"] = row.get("udm_mapping_status", "")
    return result


def print_table(results: list[dict[str, str]]) -> None:
    if not results:
        print("No matches.")
        return
    columns = ["rule_name", "license", "repository", "local_path"]
    widths = {
        column: min(48, max(len(column), *(len(row.get(column, "")) for row in results)))
        for column in columns
    }
    print("  ".join(column.ljust(widths[column]) for column in columns))
    print("  ".join("-" * widths[column] for column in columns))
    for row in results:
        print("  ".join(row.get(column, "")[: widths[column]].ljust(widths[column]) for column in columns))


def print_stats(rows: list[dict[str, str]], gcp_only: bool) -> None:
    print(f"scope={'GCP' if gcp_only else 'all'}")
    print(f"entries={len(rows)}")
    print(f"repositories={len({r.get('repository', r.get('source_repository', '')) for r in rows})}")
    print("licenses:")
    for license_name, count in sorted(Counter(r.get("license", "") for r in rows).items()):
        print(f"  {license_name or '<empty>'}: {count}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("terms", nargs="*", help="Words to search; default is OR matching")
    parser.add_argument("--all-terms", action="store_true", help="Require every search term")
    parser.add_argument("--regex", help="Case-insensitive regex over index fields and optional file content")
    parser.add_argument("--content", action="store_true", help="Also search the local rule file body")
    parser.add_argument("--gcp", action="store_true", help="Search only catalog/GCP_RULE_INDEX.csv")
    parser.add_argument("--license", help="License substring, e.g. Apache-2.0 or MIT")
    parser.add_argument("--repo", help="Repository substring")
    parser.add_argument("--category", help="Collection/category substring")
    parser.add_argument("--limit", type=int, default=50, help="Maximum results (default: 50; 0 = unlimited)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON")
    parser.add_argument("--stats", action="store_true", help="Print corpus statistics instead of searching")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    rows = rule_rows(args.gcp)
    if args.stats:
        print_stats(rows, args.gcp)
        return 0
    if not args.terms and not args.regex and not any((args.license, args.repo, args.category)):
        build_parser().print_help()
        return 2
    selected = [row for row in rows if matches(row, args)]
    if args.limit > 0:
        selected = selected[: args.limit]
    results = [public_result(row, args.gcp) for row in selected]
    if args.as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_table(results)
        print(f"\nmatches={len(results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
