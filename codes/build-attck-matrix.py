#!/usr/bin/env python3
"""
Build ATT&CK Coding Matrix (Story 1.2)

Fetches MITRE ATT&CK Enterprise v15 STIX data and generates a technique-level
coding instrument CSV. Sub-techniques are excluded per study design.

Usage:
    python build-attck-matrix.py --output data/attck-coding-matrix.csv
    python build-attck-matrix.py --output data/attck-coding-matrix.csv --dry-run

Output CSV schema:
    technique_id, technique_name, tactic, traditional_match, llm_baseline_match,
    llm_structured_match, coder_id, confidence, notes
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)

# ATT&CK Enterprise v15 STIX bundle URL (version-locked)
ATTCK_V15_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v15.1/"
    "enterprise-attack/enterprise-attack.json"
)

# ATT&CK tactic name mapping (x_mitre_shortname -> display name)
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


def fetch_attck_data(url: str) -> dict:
    """Fetch ATT&CK STIX bundle from GitHub."""
    print(f"Fetching ATT&CK STIX data from:\n  {url}")
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.json()


def extract_techniques(bundle: dict) -> list[dict]:
    """
    Extract technique-level entries from the STIX bundle.

    Filters:
    - Only 'attack-pattern' objects (techniques)
    - Only non-revoked, non-deprecated entries
    - Excludes sub-techniques (those with x_mitre_is_subtechnique=True)

    Each technique may appear under multiple tactics. We create one row per
    technique-tactic pair so coverage can be analyzed per tactic.
    """
    techniques = []

    for obj in bundle.get("objects", []):
        # Filter to attack-pattern (technique) objects only
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked or deprecated entries
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Skip sub-techniques — study codes at technique level only
        if obj.get("x_mitre_is_subtechnique", False):
            continue

        # Extract technique ID from external references
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        technique_name = obj.get("name", "Unknown")

        # Extract tactics from kill_chain_phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        # Create one row per technique-tactic combination
        for tactic in tactics:
            techniques.append(
                {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": tactic,
                }
            )

    return techniques


def build_coding_matrix(techniques: list[dict]) -> pd.DataFrame:
    """
    Build the coding matrix DataFrame with empty coding columns.

    Sorts by tactic order (following ATT&CK kill chain), then by technique ID.
    """
    df = pd.DataFrame(techniques)

    # Sort by tactic order, then technique ID
    tactic_sort = {t: i for i, t in enumerate(TACTIC_ORDER)}
    df["tactic_sort"] = df["tactic"].map(tactic_sort).fillna(99)
    df = df.sort_values(["tactic_sort", "technique_id"]).drop(columns=["tactic_sort"])

    # Add empty coding columns per the study schema
    df["traditional_match"] = ""
    df["llm_baseline_match"] = ""
    df["llm_structured_match"] = ""
    df["coder_id"] = ""
    df["confidence"] = ""
    df["notes"] = ""

    df = df.reset_index(drop=True)
    return df


def main():
    parser = argparse.ArgumentParser(
        description="Build ATT&CK Enterprise v15 technique-level coding matrix."
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/attck-coding-matrix.csv",
        help="Output CSV file path (default: data/attck-coding-matrix.csv)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and parse data but do not write output file.",
    )
    args = parser.parse_args()

    # Fetch STIX data
    bundle = fetch_attck_data(ATTCK_V15_URL)
    print(f"  STIX bundle contains {len(bundle.get('objects', []))} objects.")

    # Extract techniques
    techniques = extract_techniques(bundle)
    print(f"  Extracted {len(techniques)} technique-tactic rows.")

    # Build coding matrix
    df = build_coding_matrix(techniques)

    # Summary statistics
    unique_techniques = df["technique_id"].nunique()
    unique_tactics = df["tactic"].nunique()
    print(f"\nCoding matrix summary:")
    print(f"  Unique techniques: {unique_techniques}")
    print(f"  Tactics covered:   {unique_tactics}")
    print(f"  Total rows:        {len(df)} (technique-tactic pairs)")
    print(f"\n  Techniques per tactic:")
    for tactic in TACTIC_ORDER:
        count = len(df[df["tactic"] == tactic])
        if count > 0:
            print(f"    {tactic:<25} {count}")

    if args.dry_run:
        print(f"\n[DRY RUN] Would write {len(df)} rows to: {args.output}")
        print("\nFirst 10 rows:")
        print(df[["technique_id", "technique_name", "tactic"]].head(10).to_string())
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\nCoding matrix written to: {args.output}")


if __name__ == "__main__":
    main()
