#!/usr/bin/env python3
"""
Compute Inter-Rater Reliability — Cohen's Kappa (Story 3.3)

Loads two independent coding CSVs (one per researcher) and calculates Cohen's
kappa overall and per-tactic to quantify how much of the ATT&CK mapping
reflects genuine findings versus coder interpretation.

What Cohen's kappa measures:
    Kappa quantifies agreement between two raters beyond what would be expected
    by chance alone. A kappa of 1.0 means perfect agreement, 0 means agreement
    no better than chance, and negative values mean systematic disagreement.

Interpretation thresholds (Landis & Koch, 1977):
    >= 0.81  Almost perfect agreement
    0.61-0.80  Substantial agreement
    0.41-0.60  Moderate agreement
    0.21-0.40  Fair agreement
    <= 0.20  Slight or poor agreement

For this study: kappa >= 0.6 is adequate; < 0.6 is flagged as a validity constraint.

Usage:
    python compute-kappa.py --coder-a data/coding/researcher-a.csv --coder-b data/coding/researcher-b.csv --output data/coding/kappa-analysis.csv
    python compute-kappa.py --coder-a data/coding/researcher-a.csv --coder-b data/coding/researcher-b.csv --dry-run
"""

import argparse
import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)

try:
    from sklearn.metrics import cohen_kappa_score
except ImportError:
    print("Error: 'scikit-learn' package required. Install with: pip install scikit-learn")
    sys.exit(1)

# Methods to compare
METHODS = [
    "traditional_match",
    "llm_baseline_match",
    "llm_structured_match",
    "gemini_structured_match",
    "openai_structured_match",
]

METHOD_LABELS = {
    "traditional_match": "Traditional (ISO 27005)",
    "llm_baseline_match": "LLM Baseline (Claude)",
    "llm_structured_match": "LLM Structured (Claude)",
    "gemini_structured_match": "LLM Structured (Gemini)",
    "openai_structured_match": "LLM Structured (GPT-4o)",
}


def interpret_kappa(kappa: float) -> str:
    """Return interpretation string for a kappa value."""
    if kappa >= 0.81:
        return "Almost perfect"
    elif kappa >= 0.61:
        return "Substantial (adequate)"
    elif kappa >= 0.41:
        return "Moderate"
    elif kappa >= 0.21:
        return "Fair"
    else:
        return "Slight/poor"


def study_threshold(kappa: float) -> str:
    """Return study-specific threshold assessment."""
    if kappa >= 0.6:
        return "ADEQUATE — proceed with reconciled dataset"
    else:
        return "BELOW THRESHOLD — flag as validity constraint"


def load_coding(filepath: str, label: str) -> pd.DataFrame:
    """Load a researcher's coding CSV and validate required columns."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: {label} coding file not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)
    # Only require columns that exist in the data (new model columns may not yet be populated)
    available_methods = [m for m in METHODS if m in pd.read_csv(filepath, nrows=0).columns]
    required = ["technique_id", "tactic"] + available_methods
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"Error: {label} file missing columns: {missing}")
        sys.exit(1)

    return df


def compute_kappa_for_column(
    df_a: pd.DataFrame, df_b: pd.DataFrame, column: str, subset: pd.DataFrame = None
) -> dict:
    """
    Compute Cohen's kappa for a specific method column.

    Both DataFrames must be aligned on technique_id + tactic.
    Returns dict with kappa value, interpretation, counts.
    """
    if subset is not None:
        a_vals = subset.merge(df_a, on=["technique_id", "tactic"])[column].fillna(0).astype(int)
        b_vals = subset.merge(df_b, on=["technique_id", "tactic"])[column].fillna(0).astype(int)
    else:
        merged = df_a[["technique_id", "tactic", column]].merge(
            df_b[["technique_id", "tactic", column]],
            on=["technique_id", "tactic"],
            suffixes=("_a", "_b"),
        )
        a_vals = merged[f"{column}_a"].fillna(0).astype(int)
        b_vals = merged[f"{column}_b"].fillna(0).astype(int)

    n = len(a_vals)
    if n == 0:
        return {"kappa": float("nan"), "n": 0, "interpretation": "N/A", "threshold": "N/A"}

    agree = (a_vals == b_vals).sum()
    both_positive = ((a_vals == 1) & (b_vals == 1)).sum()
    a_only = ((a_vals == 1) & (b_vals == 0)).sum()
    b_only = ((a_vals == 0) & (b_vals == 1)).sum()

    kappa = cohen_kappa_score(a_vals, b_vals)

    return {
        "kappa": round(kappa, 3),
        "n": n,
        "agreement_pct": round(100 * agree / n, 1),
        "both_positive": int(both_positive),
        "a_only": int(a_only),
        "b_only": int(b_only),
        "interpretation": interpret_kappa(kappa),
        "threshold": study_threshold(kappa),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute Cohen's kappa for inter-rater reliability."
    )
    parser.add_argument(
        "--coder-a",
        type=str,
        required=True,
        help="Path to Researcher A's coding CSV.",
    )
    parser.add_argument(
        "--coder-b",
        type=str,
        required=True,
        help="Path to Researcher B's coding CSV.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/coding/kappa-analysis.csv",
        help="Output CSV for kappa results.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and display results without writing output.",
    )
    args = parser.parse_args()

    # Load codings
    print("Loading coding files...")
    df_a = load_coding(args.coder_a, "Researcher A")
    df_b = load_coding(args.coder_b, "Researcher B")
    print(f"  Researcher A: {len(df_a)} entries")
    print(f"  Researcher B: {len(df_b)} entries")

    # Validate alignment
    key_a = set(zip(df_a["technique_id"], df_a["tactic"]))
    key_b = set(zip(df_b["technique_id"], df_b["tactic"]))
    if key_a != key_b:
        only_a = key_a - key_b
        only_b = key_b - key_a
        print(f"\n  WARNING: Coding matrices not aligned.")
        if only_a:
            print(f"    In A but not B: {len(only_a)} entries")
        if only_b:
            print(f"    In B but not A: {len(only_b)} entries")
        print(f"    Analysis will use intersection only.\n")

    results = []

    # Overall kappa per method
    print("\n" + "=" * 70)
    print("OVERALL INTER-RATER RELIABILITY (Cohen's Kappa)")
    print("=" * 70)

    # Only compute kappa for methods present in both dataframes
    active_methods = [m for m in METHODS if m in df_a.columns and m in df_b.columns]

    for method in active_methods:
        result = compute_kappa_for_column(df_a, df_b, method)
        label = METHOD_LABELS[method]
        print(f"\n  {label}:")
        print(f"    Kappa:          {result['kappa']}")
        print(f"    Agreement:      {result['agreement_pct']}% ({result['n']} entries)")
        print(f"    Both positive:  {result['both_positive']}")
        print(f"    A only:         {result['a_only']}")
        print(f"    B only:         {result['b_only']}")
        print(f"    Interpretation: {result['interpretation']}")
        print(f"    Study threshold: {result['threshold']}")

        results.append(
            {
                "scope": "overall",
                "tactic": "all",
                "method": label,
                "kappa": result["kappa"],
                "n": result["n"],
                "agreement_pct": result["agreement_pct"],
                "interpretation": result["interpretation"],
                "threshold": result["threshold"],
            }
        )

    # Per-tactic kappa (for the primary comparison: traditional and LLM-structured)
    print("\n" + "=" * 70)
    print("PER-TACTIC KAPPA (Traditional and LLM-Structured)")
    print("=" * 70)

    # Per-tactic kappa for traditional and all structured variants
    per_tactic_methods = [m for m in active_methods if m != "llm_baseline_match"]
    tactics = sorted(df_a["tactic"].unique())
    for tactic in tactics:
        tactic_subset = df_a[df_a["tactic"] == tactic][["technique_id", "tactic"]]
        for method in per_tactic_methods:
            result = compute_kappa_for_column(df_a, df_b, method, tactic_subset)
            label = METHOD_LABELS[method]
            results.append(
                {
                    "scope": "per-tactic",
                    "tactic": tactic,
                    "method": label,
                    "kappa": result["kappa"],
                    "n": result["n"],
                    "agreement_pct": result["agreement_pct"],
                    "interpretation": result["interpretation"],
                    "threshold": result["threshold"],
                }
            )

        # Print tactic summary
        trad = [r for r in results if r["tactic"] == tactic and "Traditional" in r["method"]]
        llm = [r for r in results if r["tactic"] == tactic and "Structured" in r["method"]]
        if trad and llm:
            print(
                f"  {tactic:<25} Traditional k={trad[-1]['kappa']:<8} "
                f"LLM-Structured k={llm[-1]['kappa']}"
            )

    # Save results
    results_df = pd.DataFrame(results)

    if args.dry_run:
        print(f"\n[DRY RUN] Would write to: {args.output}")
    else:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        results_df.to_csv(args.output, index=False)
        print(f"\nKappa analysis written to: {args.output}")


if __name__ == "__main__":
    main()
