#!/usr/bin/env python3
"""
Consolidate LLM Run Outputs (Stories 2.2, 2.3)

Parses LLM run JSON outputs, extracts threat mentions, and applies the ≥2/3
union consolidation rule. Produces a consolidated CSV for each prompt variant.

The consolidation is semi-automated: this script extracts and structures the
raw outputs for researcher review. Final semantic matching (determining whether
two differently-worded threats are the same) requires researcher judgment.

Usage:
    python consolidate-runs.py --input-dir data/llm/baseline --output data/llm/baseline/consolidated.csv
    python consolidate-runs.py --input-dir data/llm/structured --output data/llm/structured/consolidated.csv
    python consolidate-runs.py --input-dir data/llm/baseline --dry-run
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)


def load_runs(input_dir: str) -> list[dict]:
    """Load all run JSON files from the input directory, sorted by run number."""
    dir_path = Path(input_dir)
    if not dir_path.exists():
        print(f"Error: Input directory not found: {input_dir}")
        sys.exit(1)

    run_files = sorted(dir_path.glob("run-*.json"))
    if not run_files:
        print(f"Error: No run-*.json files found in: {input_dir}")
        sys.exit(1)

    runs = []
    for rf in run_files:
        with open(rf, "r", encoding="utf-8") as f:
            data = json.load(f)
            runs.append(data)
        print(f"  Loaded: {rf.name} ({len(data['response'])} chars)")

    return runs


def extract_threats_from_response(response_text: str, variant: str) -> list[dict]:
    """
    Extract individual threat entries from an LLM response.

    This performs basic structural extraction. For the baseline variant,
    it looks for numbered items or headed sections. For the structured variant,
    it looks for ATT&CK technique references.

    Returns a list of dicts with 'description' and optionally 'technique_id'.
    """
    threats = []

    if variant == "structured":
        # Extract technique references from various LLM markdown formats:
        #   Claude:  "**T1591 -- Gather Victim Org Information**"
        #   GPT-4o:  "- **T1595.002 - Active Scanning: Vulnerability Scanning**"
        #   Gemini:  "### T1591 - Gather Victim Org Information"
        # We look for lines where a technique ID appears as a heading/entry.
        # Sub-technique IDs (T1234.001) are rolled up to parent (T1234).
        seen_ids = set()
        for line in response_text.split("\n"):
            # Strip common markdown prefixes: bullets, bold, headers
            stripped = line.strip()
            stripped = re.sub(r"^[-*]+\s*", "", stripped)  # bullet/list prefix
            stripped = stripped.strip("*").strip("#").strip().strip("*").strip()
            # Match technique ID (with optional sub-technique) followed by separator
            heading_match = re.match(
                r"^\*{0,2}\s*(?:#{1,4}\s*)?(?:\*{0,2}\s*)?(T\d{4})(?:\.\d{1,3})?\s*[-–—:]\s*(.+)",
                stripped,
            )
            if heading_match:
                tech_id = heading_match.group(1)  # Always parent technique (T####)
                desc = heading_match.group(2).strip().rstrip("*").strip()
                if tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    threats.append(
                        {
                            "technique_id": tech_id,
                            "description": desc[:500],
                        }
                    )

    else:
        # Baseline: extract threat scenarios from "## Threat N: Title" headings
        # Each run produces ~10 high-level narrative threat scenarios
        scenario_pattern = re.findall(
            r"##\s+Threat\s+\d+[:\s]+(.+?)(?=\n##\s+Threat\s+\d+|\n##\s+Summary|\Z)",
            response_text,
            re.DOTALL,
        )
        for item in scenario_pattern:
            # First line is the title
            title = item.strip().split("\n")[0].strip()
            if len(title) > 10:
                threats.append({"technique_id": "", "description": title[:500]})

        # Fallback: numbered lists if no scenario headers found
        if len(threats) < 3:
            numbered = re.findall(
                r"(?:^|\n)\s*\d+[\.\)]\s*\*{0,2}(.+?)(?=\n\s*\d+[\.\)]\s|\Z)",
                response_text,
                re.DOTALL,
            )
            for item in numbered:
                clean = item.strip()[:500]
                if len(clean) > 20:
                    threats.append({"technique_id": "", "description": clean})

    return threats


# Keyword themes for baseline scenario matching, ordered from most specific
# to least specific to avoid false positives (e.g., "insider" before "SWIFT",
# since an insider SWIFT threat should match insider_threat not swift_fraud).
BASELINE_THEMES = [
    ("insider_threat", ["insider threat", "insider.*abuse", "privileged.*abuse"]),
    ("vendor_vpn", ["vendor.*vpn", "temenos.*vpn", "supply chain.*temenos", "supply chain.*vpn"]),
    ("atm", ["atm", "jackpotting", "euronet"]),
    ("mssp_supply_chain", ["mssp", "managed security"]),
    ("soc_gap", ["after-hours.*soc", "soc.*gap", "dwell-time"]),
    ("cloud_misconfig", ["azure.*misconfig", "cloud.*misconfig", "cloud.*migration"]),
    ("bec", ["business email compromise", r"\bbec\b", "spearphishing.*m365"]),
    ("swift_fraud", ["swift"]),
    ("ransomware", ["ransomware"]),
    ("tpp_openbanking", ["tpp", "open banking", "psd2", "third-party provider"]),
    ("cicd_pipeline", ["ci/cd", "pipeline", "devops", "code injection"]),
    ("credential_stuffing", ["credential stuffing", "account takeover"]),
    ("espionage_apt", ["espionage", "nation-state"]),
    ("t24_legacy", ["t24", "temenos", "legacy.*java", "core banking"]),
    ("ddos", ["ddos", "denial of service"]),
]


def _classify_theme(title: str) -> str:
    """Classify a baseline scenario title into a theme using keyword matching.

    Themes are checked in priority order (most specific first) to avoid
    false positives from generic keywords like 'SWIFT' or 'intelligence'.
    """
    lower = title.lower()
    for theme, keywords in BASELINE_THEMES:
        for kw in keywords:
            if re.search(kw, lower):
                return theme
    return ""


def _consolidate_baseline_scenarios(all_run_threats: list[list[dict]]) -> list[dict]:
    """
    Consolidate baseline scenarios using keyword-based thematic matching.

    Since baseline runs produce narrative threat scenarios without technique IDs,
    we match across runs by identifying the common theme (e.g., "SWIFT fraud",
    "ransomware") in each scenario title. Unmatched scenarios get a blank theme
    and are flagged for researcher review.
    """
    all_threats = []
    theme_index = {}  # theme -> index in all_threats

    for run_idx, threats in enumerate(all_run_threats):
        for threat in threats:
            title = threat["description"].split("\n")[0][:200]
            theme = _classify_theme(title)

            if theme and theme in theme_index:
                # Same theme already seen from another run
                all_threats[theme_index[theme]][f"run_{run_idx + 1}"] = 1
            else:
                entry = {
                    "threat_id": "",
                    "technique_id": "",
                    "threat_description": title,
                    "run_1": 1 if run_idx == 0 else 0,
                    "run_2": 1 if run_idx == 1 else 0,
                    "run_3": 1 if run_idx == 2 else 0,
                    "theme": theme,  # For researcher review
                }
                if theme:
                    theme_index[theme] = len(all_threats)
                all_threats.append(entry)

    return all_threats


def main():
    parser = argparse.ArgumentParser(
        description="Consolidate LLM run outputs using ≥2/3 union rule."
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        required=True,
        help="Directory containing run-*.json files.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: <input-dir>/consolidated.csv).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and display results without writing output.",
    )
    args = parser.parse_args()

    output_path = args.output or str(Path(args.input_dir) / "consolidated.csv")

    # Load runs
    print(f"Loading runs from: {args.input_dir}")
    runs = load_runs(args.input_dir)
    print(f"  Loaded {len(runs)} runs.\n")

    variant = runs[0]["metadata"]["variant"]
    provider = runs[0]["metadata"].get("provider", "claude")

    # Prefix encodes both provider and variant for unique threat IDs
    PREFIX_MAP = {
        ("claude", "baseline"): "B",
        ("claude", "structured"): "S",
        ("gemini", "baseline"): "GB",
        ("gemini", "structured"): "GS",
        ("openai", "baseline"): "OB",
        ("openai", "structured"): "OS",
    }
    prefix = PREFIX_MAP.get((provider, variant), "X")

    # Extract threats from each run
    all_run_threats = []
    for i, run in enumerate(runs, 1):
        threats = extract_threats_from_response(run["response"], variant)
        all_run_threats.append(threats)
        print(f"  Run {i}: Extracted {len(threats)} threat entries.")

    # Build consolidated table
    # Note: This creates a flat list of all unique threats across runs.
    # Semantic matching (deciding if two threats are "the same") requires
    # researcher judgment. This script provides the structure for that review.
    print(f"\n  NOTE: Automated extraction provides a starting point.")
    print(f"  Researcher review is required for semantic matching across runs.")
    print(f"  The 'run_N' columns should be verified manually.\n")

    # Collect all unique threat descriptions across runs
    # For structured variant: match by technique_id (consistent across runs)
    # For baseline variant: match by keyword-based thematic similarity
    all_threats = []
    seen = {}  # key -> index in all_threats

    if variant == "baseline":
        # For baseline, use keyword themes to match scenarios across runs.
        # Each scenario title contains distinctive keywords (e.g., "SWIFT",
        # "ransomware", "TPP", "CI/CD") that identify the same threat theme.
        all_threats = _consolidate_baseline_scenarios(all_run_threats)
    else:
        for run_idx, threats in enumerate(all_run_threats):
            for threat in threats:
                tech_id = threat.get("technique_id", "").strip().rstrip("*")
                # Structured variant: use technique_id as the dedup key
                key = tech_id

                if key not in seen:
                    entry = {
                        "threat_id": "",  # Assigned below
                        "technique_id": tech_id,
                        "threat_description": threat["description"].split("\n")[0][:200],
                        "run_1": 1 if run_idx == 0 else 0,
                        "run_2": 1 if run_idx == 1 else 0,
                        "run_3": 1 if run_idx == 2 else 0,
                    }
                    seen[key] = len(all_threats)
                    all_threats.append(entry)
                else:
                    # Mark presence in this run
                    all_threats[seen[key]][f"run_{run_idx + 1}"] = 1

    # Assign threat IDs and compute inclusion
    for i, threat in enumerate(all_threats, 1):
        threat["threat_id"] = f"{prefix}-{i:03d}"
        run_count = threat["run_1"] + threat["run_2"] + threat["run_3"]
        threat["included"] = 1 if run_count >= 2 else 0

    df = pd.DataFrame(all_threats)
    columns = [
        "threat_id",
        "technique_id",
        "threat_description",
        "run_1",
        "run_2",
        "run_3",
        "included",
    ]
    if variant == "baseline" and "theme" in df.columns:
        columns.insert(3, "theme")
    df = df[[c for c in columns if c in df.columns]]

    # Summary
    included_count = df["included"].sum()
    total_count = len(df)
    print(f"Consolidation summary ({variant} variant):")
    print(f"  Total unique threats extracted: {total_count}")
    print(f"  Included (>=2/3 runs):          {included_count}")
    print(f"  Excluded (1/3 runs only):       {total_count - included_count}")

    if args.dry_run:
        print(f"\n[DRY RUN] Would write to: {output_path}")
        if len(df) > 0:
            print(f"\nFirst 10 entries:")
            print(df.head(10).to_string(index=False))
    else:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\nConsolidated output written to: {output_path}")


if __name__ == "__main__":
    main()
