#!/usr/bin/env python3
"""Generate coding worksheets for independent ATT&CK mapping (Stories 3.1/3.2).

Creates two identical worksheets (researcher-a.csv, researcher-b.csv) from the
ATT&CK coding matrix. The llm_structured_match column is pre-populated by
cross-referencing included technique IDs from the structured consolidated CSV
(all 80 validated as clear_match in Story 2.4). Per EC3 (ambiguous tactic
context), all tactic rows for a matching technique_id are marked 1.

Traditional and baseline columns are left empty for researcher judgment.
"""

import argparse
import os
import sys

import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate coding worksheets for independent ATT&CK mapping."
    )
    parser.add_argument(
        "--matrix",
        default="data/attck-coding-matrix.csv",
        help="Path to ATT&CK coding matrix CSV (default: data/attck-coding-matrix.csv)",
    )
    parser.add_argument(
        "--structured",
        default="data/llm/structured/consolidated.csv",
        help="Path to structured consolidated CSV (default: data/llm/structured/consolidated.csv)",
    )
    parser.add_argument(
        "--output-dir",
        default="data/coding",
        help="Output directory for worksheets (default: data/coding)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary without writing files.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # --- Load ATT&CK matrix ---
    if not os.path.isfile(args.matrix):
        print(f"Error: Matrix file not found: {args.matrix}")
        sys.exit(1)
    matrix = pd.read_csv(args.matrix)
    print(f"Loaded ATT&CK matrix: {len(matrix)} rows")

    # --- Load structured consolidated and extract included technique IDs ---
    if not os.path.isfile(args.structured):
        print(f"Error: Structured consolidated file not found: {args.structured}")
        sys.exit(1)
    structured = pd.read_csv(args.structured)
    included = structured[structured["included"] == 1]
    structured_ids = set(included["technique_id"].unique())
    print(f"Structured consolidated: {len(structured)} total, {len(included)} included, {len(structured_ids)} unique technique IDs")

    # --- Build worksheet ---
    worksheet = matrix[["technique_id", "technique_name", "tactic"]].copy()

    # Pre-populate llm_structured_match: 1 if technique_id in structured set, else 0
    # Per EC3: mark ALL tactic rows for a matching technique_id
    worksheet["traditional_match"] = pd.NA
    worksheet["llm_baseline_match"] = pd.NA
    worksheet["llm_structured_match"] = worksheet["technique_id"].apply(
        lambda tid: 1 if tid in structured_ids else 0
    )
    worksheet["confidence"] = pd.NA
    worksheet["notes"] = pd.NA

    # --- Summary ---
    structured_marked = int(worksheet["llm_structured_match"].sum())
    structured_techniques = worksheet[worksheet["llm_structured_match"] == 1]["technique_id"].nunique()
    print(f"\nWorksheet summary:")
    print(f"  Total rows: {len(worksheet)}")
    print(f"  Structured match rows: {structured_marked} ({structured_techniques} unique technique IDs)")
    print(f"  Traditional match: empty (researcher fills)")
    print(f"  Baseline match: empty (researcher fills)")

    if args.dry_run:
        print("\n[DRY RUN] No files written.")
        return

    # --- Write worksheets ---
    os.makedirs(args.output_dir, exist_ok=True)

    for coder_id, filename in [("A", "researcher-a.csv"), ("B", "researcher-b.csv")]:
        ws = worksheet.copy()
        ws["coder_id"] = coder_id
        # Reorder columns to match schema
        ws = ws[
            [
                "technique_id",
                "technique_name",
                "tactic",
                "traditional_match",
                "llm_baseline_match",
                "llm_structured_match",
                "coder_id",
                "confidence",
                "notes",
            ]
        ]
        outpath = os.path.join(args.output_dir, filename)
        ws.to_csv(outpath, index=False)
        print(f"Written: {outpath}")

    print("\nDone. Researchers can now fill traditional_match and llm_baseline_match columns.")


if __name__ == "__main__":
    main()
