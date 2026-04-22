#!/usr/bin/env python3
"""
Compute Overlap and Unique Contributions — Jaccard Index (Story 4.2)

Computes the Jaccard similarity coefficient between method pairs and
decomposes technique sets into shared, traditional-only, and LLM-only groups.

Why Jaccard matters:
    Jaccard = |A ∩ B| / |A ∪ B|
    It measures how similar two sets are, ranging from 0 (no overlap) to 1
    (identical). For this study, a low Jaccard means the methods are
    complementary (each finds different things), while a high Jaccard means
    they're redundant (both find the same things). Complementarity is the
    stronger argument for hybrid approaches.

Usage:
    python compute-overlap.py --input data/coding/reconciled-final.csv --output data/analysis/overlap-jaccard.csv
    python compute-overlap.py --input data/coding/reconciled-final.csv --dry-run
"""

import argparse
import sys
from itertools import combinations
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)


def jaccard(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity coefficient."""
    union = set_a | set_b
    if len(union) == 0:
        return 0.0
    return len(set_a & set_b) / len(union)


def decompose(set_a: set, set_b: set, label_a: str, label_b: str) -> dict:
    """Decompose two sets into shared, A-only, and B-only."""
    shared = set_a & set_b
    a_only = set_a - set_b
    b_only = set_b - set_a
    j = jaccard(set_a, set_b)
    return {
        "jaccard": round(j, 3),
        "shared_count": len(shared),
        "a_only_count": len(a_only),
        "b_only_count": len(b_only),
        "a_total": len(set_a),
        "b_total": len(set_b),
        "union_count": len(set_a | set_b),
        "shared": sorted(shared),
        "a_only": sorted(a_only),
        "b_only": sorted(b_only),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute Jaccard overlap between methods."
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to reconciled coding CSV.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/analysis/overlap-jaccard.csv",
        help="Output CSV path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and display without writing output.",
    )
    args = parser.parse_args()

    # Load data
    path = Path(args.input)
    if not path.exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)

    # Define all possible methods and their labels
    ALL_METHODS = {
        "Traditional": "traditional_match",
        "LLM-Baseline (Claude)": "llm_baseline_match",
        "LLM-Structured (Claude)": "llm_structured_match",
        "LLM-Structured (Gemini)": "gemini_structured_match",
        "LLM-Structured (GPT-4o)": "openai_structured_match",
    }

    # Only use methods present in the dataset
    methods = {}
    for label, col in ALL_METHODS.items():
        if col in df.columns:
            df[col] = df[col].fillna(0).astype(int)
            methods[label] = col

    print(f"Loaded: {args.input} ({len(df)} rows)")
    print(f"Active methods: {', '.join(methods.keys())}")

    # Build technique sets (using technique_id as identifier)
    sets = {}
    for label, col in methods.items():
        sets[label] = set(df[df[col] == 1]["technique_id"])
        print(f"  {label}: {len(sets[label])} unique techniques")

    # All pairwise comparisons
    results = []

    print("\n" + "=" * 70)
    print(f"PAIRWISE OVERLAP ANALYSIS ({len(list(combinations(sets, 2)))} pairs)")
    print("=" * 70)

    for name_a, name_b in combinations(sets.keys(), 2):
        set_a, set_b = sets[name_a], sets[name_b]
        d = decompose(set_a, set_b, name_a, name_b)
        comp_label = f"{name_a} vs {name_b}"

        print(f"\n  {comp_label}:")
        print(f"    Jaccard index:   {d['jaccard']}")
        print(f"    Shared:          {d['shared_count']} techniques")
        print(f"    {name_a} only:  {d['a_only_count']} techniques")
        print(f"    {name_b} only:  {d['b_only_count']} techniques")
        print(f"    Union:           {d['union_count']} techniques")

        results.append(
            {
                "comparison": comp_label,
                "method_a": name_a,
                "method_b": name_b,
                "jaccard": d["jaccard"],
                "shared": d["shared_count"],
                "a_only": d["a_only_count"],
                "b_only": d["b_only_count"],
                "a_total": d["a_total"],
                "b_total": d["b_total"],
                "union": d["union_count"],
            }
        )

    # Cross-model structured comparison (if multiple structured variants exist)
    structured_labels = [l for l in sets if "Structured" in l]
    if len(structured_labels) >= 2:
        print("\n" + "=" * 70)
        print("CROSS-MODEL STRUCTURED COMPARISON")
        print("=" * 70)
        all_structured_union = set()
        all_structured_intersection = None
        for label in structured_labels:
            all_structured_union |= sets[label]
            if all_structured_intersection is None:
                all_structured_intersection = sets[label].copy()
            else:
                all_structured_intersection &= sets[label]
        print(f"\n  Models compared: {', '.join(structured_labels)}")
        print(f"  Union of all structured:        {len(all_structured_union)} techniques")
        print(f"  Intersection of all structured:  {len(all_structured_intersection)} techniques")
        print(f"  Consensus rate: {len(all_structured_intersection)}/{len(all_structured_union)} = "
              f"{100*len(all_structured_intersection)/len(all_structured_union):.1f}%"
              if all_structured_union else "  No techniques found")

    # Traditional + all structured union
    if "Traditional" in sets and structured_labels:
        trad_set = sets["Traditional"]
        all_struct_union = set()
        for label in structured_labels:
            all_struct_union |= sets[label]
        combined = trad_set | all_struct_union
        print(f"\n  Traditional + all structured union: {len(combined)} techniques")
        print(f"  Traditional-only (not in any structured): {len(trad_set - all_struct_union)} techniques")

    # Primary comparison detail: Traditional vs each structured
    print("\n" + "=" * 70)
    print("TECHNIQUE-LEVEL DETAIL: Traditional vs LLM-Structured (Claude)")
    print("=" * 70)

    if "Traditional" in sets and "LLM-Structured (Claude)" in sets:
        d = decompose(sets["Traditional"], sets["LLM-Structured (Claude)"], "Traditional", "LLM-Structured (Claude)")

        if d["shared"]:
            print(f"\n  Shared techniques ({d['shared_count']}):")
            for t in d["shared"]:
                name = df[df["technique_id"] == t]["technique_name"].iloc[0] if "technique_name" in df.columns else ""
                print(f"    {t} {name}")

        if d["a_only"]:
            print(f"\n  Traditional-only techniques ({d['a_only_count']}):")
            for t in d["a_only"]:
                name = df[df["technique_id"] == t]["technique_name"].iloc[0] if "technique_name" in df.columns else ""
                print(f"    {t} {name}")

        if d["b_only"]:
            print(f"\n  LLM-Structured (Claude)-only techniques ({d['b_only_count']}):")
            for t in d["b_only"]:
                name = df[df["technique_id"] == t]["technique_name"].iloc[0] if "technique_name" in df.columns else ""
                print(f"    {t} {name}")

    # Save
    results_df = pd.DataFrame(results)

    if args.dry_run:
        print(f"\n[DRY RUN] Would write to: {args.output}")
    else:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        results_df.to_csv(args.output, index=False)
        print(f"\nOverlap analysis written to: {args.output}")


if __name__ == "__main__":
    main()
