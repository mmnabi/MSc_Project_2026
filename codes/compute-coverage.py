#!/usr/bin/env python3
"""
Compute Coverage Ratios (Story 4.1)

Loads the reconciled dataset and computes what percentage of ATT&CK Enterprise
techniques each method identified, broken down by tactic. This produces the
coverage profiles — the study's primary empirical output.

Why coverage matters:
    Coverage ratio = (techniques identified by method) / (total techniques in tactic)
    This measures how thoroughly each method scans the threat landscape.
    A method with 80% coverage in Initial Access but 10% in Collection has a
    characteristic blind spot — and that asymmetry is the most interesting finding.

Usage:
    python compute-coverage.py --input data/coding/reconciled-final.csv --output data/analysis/coverage-ratios.csv
    python compute-coverage.py --input data/coding/reconciled-final.csv --dry-run
"""

import argparse
import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)

ALL_METHODS = [
    "traditional_match",
    "llm_baseline_match",
    "llm_structured_match",
    "gemini_structured_match",
    "openai_structured_match",
]

ALL_METHOD_LABELS = {
    "traditional_match": "Traditional",
    "llm_baseline_match": "LLM Base (Claude)",
    "llm_structured_match": "LLM Struct (Claude)",
    "gemini_structured_match": "LLM Struct (Gemini)",
    "openai_structured_match": "LLM Struct (GPT-4o)",
}

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def main():
    parser = argparse.ArgumentParser(description="Compute coverage ratios by tactic.")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to reconciled coding CSV.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/analysis/coverage-ratios.csv",
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

    # Only use methods that exist in the dataset
    METHODS = [m for m in ALL_METHODS if m in df.columns]
    METHOD_LABELS = {m: ALL_METHOD_LABELS[m] for m in METHODS}

    for method in METHODS:
        df[method] = df[method].fillna(0).astype(int)

    print(f"Loaded: {args.input} ({len(df)} technique-tactic rows)")
    print(f"Active methods: {', '.join(METHOD_LABELS[m] for m in METHODS)}")

    results = []

    # Overall coverage
    print("\n" + "=" * 70)
    print("OVERALL COVERAGE")
    print("=" * 70)

    total = len(df)
    for method in METHODS:
        identified = df[method].sum()
        ratio = round(100 * identified / total, 1) if total > 0 else 0
        label = METHOD_LABELS[method]
        print(f"  {label:<25} {identified:>4} / {total} techniques = {ratio}%")
        results.append(
            {
                "tactic": "OVERALL",
                "method": label,
                "techniques_identified": int(identified),
                "techniques_total": total,
                "coverage_pct": ratio,
            }
        )

    # Per-tactic coverage
    print("\n" + "=" * 70)
    print("PER-TACTIC COVERAGE")
    print("=" * 70)

    col_width = max(18, max(len(METHOD_LABELS[m]) for m in METHODS) + 2)
    header = f"  {'Tactic':<25}"
    for method in METHODS:
        header += f" {METHOD_LABELS[method]:>{col_width}}"
    print(header)
    print("  " + "-" * (25 + col_width * len(METHODS)))

    for tactic in TACTIC_ORDER:
        tactic_df = df[df["tactic"] == tactic]
        tactic_total = len(tactic_df)
        if tactic_total == 0:
            continue

        row = f"  {tactic:<25}"
        for method in METHODS:
            identified = tactic_df[method].sum()
            ratio = round(100 * identified / tactic_total, 1)
            cell = f"{identified:>3}/{tactic_total:<3} ({ratio:>5.1f}%)"
            row += f" {cell:>{col_width}}"
            label = METHOD_LABELS[method]
            results.append(
                {
                    "tactic": tactic,
                    "method": label,
                    "techniques_identified": int(identified),
                    "techniques_total": tactic_total,
                    "coverage_pct": ratio,
                }
            )
        print(row)

    # Save results
    results_df = pd.DataFrame(results)

    if args.dry_run:
        print(f"\n[DRY RUN] Would write to: {args.output}")
    else:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        results_df.to_csv(args.output, index=False)
        print(f"\nCoverage ratios written to: {args.output}")


if __name__ == "__main__":
    main()
