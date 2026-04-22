#!/usr/bin/env python3
"""
populate-coding-worksheet.py

Reads threat-to-technique mapping CSVs (traditional and baseline) and populates
the researcher coding worksheet with binary match columns, confidence, and notes.

Usage:
    python scripts/populate-coding-worksheet.py [--dry-run]
    python scripts/populate-coding-worksheet.py --worksheet path --trad-mappings path --base-mappings path
"""

import argparse
import pandas as pd
import sys
import os


def load_and_validate_mappings(mapping_path, valid_technique_ids, source_label):
    """Load a mapping CSV and validate technique_ids against the worksheet."""
    df = pd.read_csv(mapping_path)
    required_cols = {"threat_id", "technique_id", "confidence", "rationale"}
    missing = required_cols - set(df.columns)
    if missing:
        print(f"ERROR: {source_label} mapping file missing columns: {missing}")
        sys.exit(1)

    # Validate technique_ids
    unknown = set(df["technique_id"]) - valid_technique_ids
    if unknown:
        print(f"WARNING: {source_label} mappings reference unknown technique_ids: {sorted(unknown)}")
        print("  These will be ignored (no matching row in worksheet).")

    # Validate confidence values
    valid_conf = {"clear", "plausible"}
    bad_conf = set(df["confidence"]) - valid_conf
    if bad_conf:
        print(f"ERROR: {source_label} mappings have invalid confidence values: {bad_conf}")
        sys.exit(1)

    print(f"  {source_label}: {len(df)} mapping rows, "
          f"{df['threat_id'].nunique()} threats, "
          f"{df['technique_id'].nunique()} unique techniques")
    return df


def compute_matches(worksheet, trad_mappings, base_mappings):
    """Compute binary matches and populate worksheet columns."""
    # Get sets of matched technique_ids
    trad_techniques = set(trad_mappings["technique_id"])
    base_techniques = set(base_mappings["technique_id"])

    # Build notes lookup: technique_id -> list of threat_ids per source
    trad_notes = {}
    for _, row in trad_mappings.iterrows():
        trad_notes.setdefault(row["technique_id"], []).append(row["threat_id"])
    base_notes = {}
    for _, row in base_mappings.iterrows():
        base_notes.setdefault(row["technique_id"], []).append(row["threat_id"])

    # Build confidence lookup: technique_id -> highest confidence across all mappings
    # Priority: clear > plausible
    conf_priority = {"clear": 2, "plausible": 1}
    conf_lookup = {}
    for mappings in [trad_mappings, base_mappings]:
        for _, row in mappings.iterrows():
            tid = row["technique_id"]
            conf = row["confidence"]
            current = conf_lookup.get(tid, 0)
            conf_lookup[tid] = max(current, conf_priority.get(conf, 0))
    # Also include llm_structured_match confidence (all structured matches are clear)
    # per ambiguity classification results

    # Reverse priority map
    priority_to_conf = {2: "clear", 1: "plausible", 0: ""}

    # Pre-fill columns with proper types to avoid FutureWarning
    worksheet["confidence"] = worksheet["confidence"].fillna("").astype(str)
    worksheet["notes"] = worksheet["notes"].fillna("").astype(str)

    # Populate worksheet
    for idx, row in worksheet.iterrows():
        tid = row["technique_id"]

        # Traditional match
        worksheet.at[idx, "traditional_match"] = 1 if tid in trad_techniques else 0

        # Baseline match
        worksheet.at[idx, "llm_baseline_match"] = 1 if tid in base_techniques else 0

        # Notes: compact source references
        parts = []
        if tid in trad_notes:
            # Deduplicate threat_ids (same technique can be mapped multiple times)
            unique_trad = sorted(set(trad_notes[tid]))
            parts.append("trad:" + ",".join(unique_trad))
        if tid in base_notes:
            unique_base = sorted(set(base_notes[tid]))
            parts.append("base:" + ",".join(unique_base))
        if parts:
            worksheet.at[idx, "notes"] = "; ".join(parts)

        # Confidence: highest across all methods (including structured)
        struct_match = row.get("llm_structured_match", 0)
        highest = conf_lookup.get(tid, 0)
        if struct_match == 1:
            # Structured matches were all clear per ambiguity classification
            highest = max(highest, 2)
        worksheet.at[idx, "confidence"] = priority_to_conf.get(highest, "")

    return worksheet


def print_summary(worksheet, trad_mappings, base_mappings):
    """Print summary statistics to stdout."""
    trad_count = int(worksheet["traditional_match"].sum())
    base_count = int(worksheet["llm_baseline_match"].sum())
    struct_count = int(worksheet["llm_structured_match"].sum())
    total_rows = len(worksheet)

    # Count unique techniques (not rows, since techniques can appear in multiple tactics)
    trad_unique = worksheet[worksheet["traditional_match"] == 1]["technique_id"].nunique()
    base_unique = worksheet[worksheet["llm_baseline_match"] == 1]["technique_id"].nunique()
    struct_unique = worksheet[worksheet["llm_structured_match"] == 1]["technique_id"].nunique()

    print("\n=== Worksheet Population Summary ===")
    print(f"Total rows: {total_rows}")
    print(f"Traditional match:   {trad_count} rows ({trad_unique} unique techniques)")
    print(f"Baseline match:      {base_count} rows ({base_unique} unique techniques)")
    print(f"Structured match:    {struct_count} rows ({struct_unique} unique techniques) [unchanged]")

    # Confidence breakdown
    conf_counts = worksheet["confidence"].value_counts()
    print(f"\nConfidence distribution:")
    for conf_val in ["clear", "plausible", ""]:
        count = conf_counts.get(conf_val, 0)
        label = conf_val if conf_val else "(none)"
        print(f"  {label}: {count}")

    # Coverage by tactic
    print(f"\nCoverage by tactic:")
    print(f"  {'Tactic':<30} {'Rows':>5} {'Trad':>5} {'Base':>5} {'Struct':>7}")
    print(f"  {'-'*30} {'-'*5} {'-'*5} {'-'*5} {'-'*7}")
    for tactic in worksheet["tactic"].unique():
        tactic_df = worksheet[worksheet["tactic"] == tactic]
        t_rows = len(tactic_df)
        t_trad = int(tactic_df["traditional_match"].sum())
        t_base = int(tactic_df["llm_baseline_match"].sum())
        t_struct = int(tactic_df["llm_structured_match"].sum())
        print(f"  {tactic:<30} {t_rows:>5} {t_trad:>5} {t_base:>5} {t_struct:>7}")

    # Set overlap
    trad_set = set(worksheet[worksheet["traditional_match"] == 1]["technique_id"])
    base_set = set(worksheet[worksheet["llm_baseline_match"] == 1]["technique_id"])
    struct_set = set(worksheet[worksheet["llm_structured_match"] == 1]["technique_id"])

    print(f"\nTechnique-level overlap (unique technique_ids):")
    print(f"  Trad & Base:     {len(trad_set & base_set)}")
    print(f"  Trad & Struct:   {len(trad_set & struct_set)}")
    print(f"  Base & Struct:   {len(base_set & struct_set)}")
    print(f"  All three:       {len(trad_set & base_set & struct_set)}")
    print(f"  Trad only:       {len(trad_set - base_set - struct_set)}")
    print(f"  Base only:       {len(base_set - trad_set - struct_set)}")
    print(f"  Struct only:     {len(struct_set - trad_set - base_set)}")

    # Mapping source counts
    print(f"\nMapping source summary:")
    print(f"  Traditional threats mapped: {trad_mappings['threat_id'].nunique()}")
    print(f"  Traditional mapping rows:   {len(trad_mappings)}")
    print(f"  Baseline scenarios mapped:  {base_mappings['threat_id'].nunique()}")
    print(f"  Baseline mapping rows:      {len(base_mappings)}")


def main():
    parser = argparse.ArgumentParser(
        description="Populate researcher coding worksheet from threat-to-technique mappings"
    )
    parser.add_argument(
        "--worksheet",
        default="data/coding/researcher-a.csv",
        help="Path to the researcher coding worksheet CSV"
    )
    parser.add_argument(
        "--trad-mappings",
        default="data/coding/mappings/traditional-mappings.csv",
        help="Path to traditional threat mappings CSV"
    )
    parser.add_argument(
        "--base-mappings",
        default="data/coding/mappings/baseline-mappings.csv",
        help="Path to baseline scenario mappings CSV"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (defaults to overwriting worksheet)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and print summary without writing output"
    )
    args = parser.parse_args()

    # Resolve paths relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    def resolve(path):
        if os.path.isabs(path):
            return path
        return os.path.join(project_root, path)

    worksheet_path = resolve(args.worksheet)
    trad_path = resolve(args.trad_mappings)
    base_path = resolve(args.base_mappings)
    output_path = resolve(args.output) if args.output else worksheet_path

    # Load worksheet
    print(f"Loading worksheet: {worksheet_path}")
    worksheet = pd.read_csv(worksheet_path)
    print(f"  {len(worksheet)} rows, {worksheet['technique_id'].nunique()} unique techniques")

    # Validate worksheet columns
    required = {"technique_id", "technique_name", "tactic", "traditional_match",
                "llm_baseline_match", "llm_structured_match", "coder_id", "confidence", "notes"}
    missing = required - set(worksheet.columns)
    if missing:
        print(f"ERROR: Worksheet missing columns: {missing}")
        sys.exit(1)

    valid_technique_ids = set(worksheet["technique_id"])

    # Load and validate mappings
    print(f"\nLoading mappings:")
    trad_mappings = load_and_validate_mappings(trad_path, valid_technique_ids, "Traditional")
    base_mappings = load_and_validate_mappings(base_path, valid_technique_ids, "Baseline")

    # Compute matches
    print(f"\nComputing matches...")
    worksheet = compute_matches(worksheet, trad_mappings, base_mappings)

    # Print summary
    print_summary(worksheet, trad_mappings, base_mappings)

    if args.dry_run:
        print(f"\n[DRY RUN] No files written.")
    else:
        # Ensure integer types for match columns
        worksheet["traditional_match"] = worksheet["traditional_match"].astype(int)
        worksheet["llm_baseline_match"] = worksheet["llm_baseline_match"].astype(int)
        worksheet["llm_structured_match"] = worksheet["llm_structured_match"].astype(int)

        worksheet.to_csv(output_path, index=False)
        print(f"\nWorksheet written to: {output_path}")


if __name__ == "__main__":
    main()
