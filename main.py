#!/usr/bin/env python3
"""CLI entry point for the AWS Cloud Security Auditor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from auditor.runner import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the read-only AWS Cloud Security Misconfiguration Auditor."
    )
    parser.add_argument("--region", default=None, help="AWS region, e.g. eu-central-1")
    parser.add_argument("--profile", default="default", help="Existing AWS profile")
    parser.add_argument(
        "--output-dir", "--output",
        dest="output_dir",
        default="reports",
        help="Directory for generated HTML/JSON reports",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    region = args.region
    if not region:
        # Preserve a useful CLI default without requiring interactive input.
        region = "eu-central-1"

    try:
        result = run_audit(
            region=region,
            profile=args.profile,
            output_dir=Path(args.output_dir),
        )
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    summary = result["summary"]
    print("AWS Cloud Security Auditor")
    print(f"Account : {result['account_id']}")
    print(f"Region  : {result['region']}")
    print(f"Profile : {result['profile']}")
    print(f"Duration: {result['duration_seconds']:.2f}s")
    print(f"HTML    : {result['html_report']}")
    print(f"JSON    : {result['json_report']}")
    print()
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
