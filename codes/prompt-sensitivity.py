#!/usr/bin/env python3
"""
Prompt Sensitivity Analysis (Story 4.4)

Compares LLM-baseline and LLM-structured consolidated outputs to measure
how explicit ATT&CK framing changes coverage. This directly addresses the
prompt engineering confound that would otherwise undermine the LLM evaluation.

Key questions this analysis answers:
    1. How many techniques are gained by adding ATT&CK framing?
    2. How many techniques are lost (present in baseline, absent in structured)?
    3. Do changes cluster in specific tactics or spread uniformly?
    4. Does structured prompting increase depth or breadth?

Usage:
    python prompt-sensitivity.py --input data/coding/reconciled-final.csv --output data/analysis/prompt-sensitivity.csv
    python prompt-sensitivity.py --input data/coding/reconciled-final.csv --dry-run
"""

import argparse
import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)

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
    parser = argparse.ArgumentParser(
        description="Analyze prompt sensitivity: baseline vs structured LLM outputs."
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
        default="data/analysis/prompt-sensitivity.csv",
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
    df["llm_baseline_match"] = df["llm_baseline_match"].fillna(0).astype(int)
    df["llm_structured_match"] = df["llm_structured_match"].fillna(0).astype(int)

    print(f"Loaded: {args.input} ({len(df)} rows)")

    # Classify each technique-tactic row
    df["change"] = "unchanged"
    df.loc[
        (df["llm_baseline_match"] == 0) & (df["llm_structured_match"] == 1), "change"
    ] = "gained"
    df.loc[
        (df["llm_baseline_match"] == 1) & (df["llm_structured_match"] == 0), "change"
    ] = "lost"
    df.loc[
        (df["llm_baseline_match"] == 1) & (df["llm_structured_match"] == 1), "change"
    ] = "retained"

    # Overall summary
    print("\n" + "=" * 70)
    print("PROMPT SENSITIVITY: Baseline -> Structured")
    print("=" * 70)

    baseline_total = df["llm_baseline_match"].sum()
    structured_total = df["llm_structured_match"].sum()
    gained = (df["change"] == "gained").sum()
    lost = (df["change"] == "lost").sum()
    retained = (df["change"] == "retained").sum()

    print(f"\n  Baseline techniques:    {baseline_total}")
    print(f"  Structured techniques:  {structured_total}")
    print(f"  Net change:             {structured_total - baseline_total:+d}")
    print(f"\n  Retained (both):        {retained}")
    print(f"  Gained (struct only):   {gained}")
    print(f"  Lost (base only):       {lost}")

    # Per-tactic breakdown
    print("\n" + "=" * 70)
    print("PER-TACTIC CHANGES")
    print("=" * 70)

    results = []
    header = f"  {'Tactic':<25} {'Base':>5} {'Struct':>6} {'Gain':>5} {'Lost':>5} {'Net':>5}"
    print(header)
    print("  " + "-" * 55)

    for tactic in TACTIC_ORDER:
        t_df = df[df["tactic"] == tactic]
        if len(t_df) == 0:
            continue

        base_n = t_df["llm_baseline_match"].sum()
        struct_n = t_df["llm_structured_match"].sum()
        t_gained = (t_df["change"] == "gained").sum()
        t_lost = (t_df["change"] == "lost").sum()
        net = struct_n - base_n

        print(
            f"  {tactic:<25} {base_n:>5} {struct_n:>6} {t_gained:>5} "
            f"{t_lost:>5} {net:>+5}"
        )

        results.append(
            {
                "tactic": tactic,
                "baseline_count": int(base_n),
                "structured_count": int(struct_n),
                "gained": int(t_gained),
                "lost": int(t_lost),
                "net_change": int(net),
                "tactic_total": len(t_df),
            }
        )

    # Characterization
    print("\n" + "=" * 70)
    print("CHARACTERIZATION")
    print("=" * 70)

    # Does structured prompting increase breadth (new tactics) or depth (more in existing)?
    base_tactics = set(df[df["llm_baseline_match"] == 1]["tactic"])
    struct_tactics = set(df[df["llm_structured_match"] == 1]["tactic"])
    new_tactics = struct_tactics - base_tactics
    lost_tactics = base_tactics - struct_tactics

    print(f"\n  Tactics with baseline coverage:    {len(base_tactics)}")
    print(f"  Tactics with structured coverage:  {len(struct_tactics)}")
    if new_tactics:
        print(f"  New tactics gained: {', '.join(sorted(new_tactics))}")
    if lost_tactics:
        print(f"  Tactics lost:       {', '.join(sorted(lost_tactics))}")
    if not new_tactics and not lost_tactics:
        print(f"  Same tactics covered — changes are in depth, not breadth.")

    # Gained techniques detail
    gained_df = df[df["change"] == "gained"]
    if len(gained_df) > 0:
        print(f"\n  Gained techniques ({len(gained_df)}):")
        for _, row in gained_df.iterrows():
            name = row.get("technique_name", "")
            print(f"    {row['technique_id']} {name} [{row['tactic']}]")

    # Lost techniques detail
    lost_df = df[df["change"] == "lost"]
    if len(lost_df) > 0:
        print(f"\n  Lost techniques ({len(lost_df)}):")
        for _, row in lost_df.iterrows():
            name = row.get("technique_name", "")
            print(f"    {row['technique_id']} {name} [{row['tactic']}]")

    # Cross-model structured comparison (if Gemini/GPT columns exist)
    STRUCTURED_COLS = {
        "Claude": "llm_structured_match",
        "Gemini": "gemini_structured_match",
        "GPT-4o": "openai_structured_match",
    }
    active_structured = {k: v for k, v in STRUCTURED_COLS.items() if v in df.columns}

    if len(active_structured) > 1:
        print("\n" + "=" * 70)
        print("CROSS-MODEL STRUCTURED COMPARISON")
        print("=" * 70)

        for col in active_structured.values():
            df[col] = df[col].fillna(0).astype(int)

        # Per-tactic counts for each model
        header = f"  {'Tactic':<25}"
        for model_name in active_structured:
            header += f" {model_name:>10}"
        print(header)
        print("  " + "-" * (25 + 10 * len(active_structured)))

        cross_model_results = []
        for tactic in TACTIC_ORDER:
            t_df = df[df["tactic"] == tactic]
            if len(t_df) == 0:
                continue
            row_str = f"  {tactic:<25}"
            row_data = {"tactic": tactic, "tactic_total": len(t_df)}
            for model_name, col in active_structured.items():
                count = int(t_df[col].sum())
                row_str += f" {count:>10}"
                row_data[f"{model_name}_count"] = count
            print(row_str)
            cross_model_results.append(row_data)

        # Summary: consensus techniques (identified by ALL structured models)
        all_sets = {}
        for model_name, col in active_structured.items():
            all_sets[model_name] = set(df[df[col] == 1]["technique_id"])

        consensus = set.intersection(*all_sets.values()) if all_sets else set()
        any_model = set.union(*all_sets.values()) if all_sets else set()
        print(f"\n  Consensus (all models): {len(consensus)} techniques")
        print(f"  Any model:             {len(any_model)} techniques")
        for model_name, s in all_sets.items():
            unique = s - set.union(*(v for k, v in all_sets.items() if k != model_name))
            print(f"  {model_name}-only:          {len(unique)} techniques")

    # Save
    results_df = pd.DataFrame(results)

    if args.dry_run:
        print(f"\n[DRY RUN] Would write to: {args.output}")
    else:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        results_df.to_csv(args.output, index=False)
        print(f"\nPrompt sensitivity analysis written to: {args.output}")


if __name__ == "__main__":
    main()
