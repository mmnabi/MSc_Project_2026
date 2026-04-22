#!/usr/bin/env python3
"""
Story 2.4 -- Classify LLM Output Ambiguity

Classifies each LLM-generated threat/technique by mappability to ATT&CK v15:
  - clear_match:    unambiguous mapping to ATT&CK technique(s)
  - plausible_match: defensible mapping requiring researcher judgment
  - no_match:       too vague or no ATT&CK technique correspondence

Structured variant: automated EC5 cross-reference (technique ID + name validation).
Baseline variant:   pre-populated classification based on behavioral specificity (GP3/GP5).

Outputs:
  data/llm/structured/ambiguity-classification.csv
  data/llm/baseline/ambiguity-classification.csv
"""

import argparse
import csv
import os
import sys
from difflib import SequenceMatcher


def load_attck_matrix(path):
    """Load ATT&CK coding matrix and build technique_id -> technique_name lookup.

    Since techniques appear under multiple tactics, we deduplicate by technique_id
    (names are the same across tactic rows).
    """
    techniques = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["technique_id"].strip()
            tname = row["technique_name"].strip()
            if tid not in techniques:
                techniques[tid] = tname
    return techniques


def normalize_name(name):
    """Normalize a technique name for comparison: lowercase, strip whitespace,
    remove common variations (slashes, parentheses, 'or' vs '/')."""
    import re
    n = name.lower().strip()
    # Remove parenthetical notes like "(Ransomware)" that LLMs may add
    n = re.sub(r"\s*\([^)]*\)\s*", " ", n).strip()
    # Normalize common ATT&CK name patterns
    n = n.replace("/", " or ")
    n = n.replace("  ", " ")
    return n


def name_similarity(name_a, name_b):
    """Return similarity ratio between two technique names (0.0 to 1.0).

    Uses SequenceMatcher plus a containment check: if one normalized name
    contains the other, boost similarity (handles 'Domain Policy Modification'
    vs 'Domain or Tenant Policy Modification' cases).
    """
    na = normalize_name(name_a)
    nb = normalize_name(name_b)
    sim = SequenceMatcher(None, na, nb).ratio()

    # Containment boost: if the shorter name is fully contained in the longer
    # one, treat as high similarity (LLM may abbreviate canonical names)
    shorter, longer = (na, nb) if len(na) <= len(nb) else (nb, na)
    if shorter in longer:
        sim = max(sim, 0.90)

    return sim


def classify_structured(structured_path, attck_lookup):
    """Classify structured LLM outputs using EC5 cross-reference.

    For each included technique:
      1. Check if technique_id exists in ATT&CK v15 matrix
      2. Compare threat_description against canonical technique name
      3. Assign ambiguity class based on match quality
    """
    results = []

    with open(structured_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("included", "0").strip() != "1":
                continue

            threat_id = row["threat_id"].strip()
            technique_id = row["technique_id"].strip()
            description = row["threat_description"].strip()

            # EC5 check: does the technique ID exist in v15?
            if technique_id not in attck_lookup:
                results.append({
                    "threat_id": threat_id,
                    "technique_id": technique_id,
                    "threat_description": description,
                    "ambiguity_class": "no_match",
                    "rationale": f"EC5: technique ID {technique_id} not found in ATT&CK v15 matrix (possible hallucination)"
                })
                continue

            canonical_name = attck_lookup[technique_id]
            sim = name_similarity(description, canonical_name)

            if sim >= 0.80:
                # High similarity -- clear match
                results.append({
                    "threat_id": threat_id,
                    "technique_id": technique_id,
                    "threat_description": description,
                    "ambiguity_class": "clear_match",
                    "rationale": f"EC5: valid ID, name matches canonical '{canonical_name}' (similarity {sim:.2f})"
                })
            elif sim >= 0.55:
                # Moderate similarity -- name is close but not exact
                results.append({
                    "threat_id": threat_id,
                    "technique_id": technique_id,
                    "threat_description": description,
                    "ambiguity_class": "plausible_match",
                    "rationale": f"EC5: valid ID, name partially matches canonical '{canonical_name}' (similarity {sim:.2f}); verify behavior"
                })
            else:
                # Valid ID but very different name -- LLM may have assigned wrong ID
                results.append({
                    "threat_id": threat_id,
                    "technique_id": technique_id,
                    "threat_description": description,
                    "ambiguity_class": "plausible_match",
                    "rationale": f"EC5: valid ID but name '{description}' differs from canonical '{canonical_name}' (similarity {sim:.2f}); verify correct technique"
                })

    return results


# Pre-populated baseline classifications based on behavioral specificity analysis.
# Each scenario was assessed against GP3 (explicit/strongly implied ATT&CK behavior)
# and GP5 (too vague to map). Researcher should review these before finalizing.
BASELINE_CLASSIFICATIONS = {
    "B-001": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly describes ransomware deployment (T1486) and AD compromise; "
                     "multi-step narrative with concrete ATT&CK-level behaviors"
    },
    "B-002": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly describes SWIFT fraud (T1657), compromised credentials (T1078), "
                     "and lateral movement into secure zone; specific financial attack chain"
    },
    "B-003": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: describes compromised TPP (T1199 trusted relationship), unauthorized "
                     "PSD2 payment initiation (T1657); specific supply chain + fraud scenario"
    },
    "B-004": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly describes CI/CD pipeline compromise (T1195 supply chain), "
                     "malicious code injection into production; concrete DevOps attack scenario"
    },
    "B-005": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly names credential stuffing (T1110 brute force) against "
                     "specific platforms (web/mobile banking); unambiguous technique-level behavior"
    },
    "B-007": {
        "ambiguity_class": "plausible_match",
        "rationale": "GP3/GP5: describes privileged insider threat with SWIFT/core banking context, "
                     "but 'insider threat' is partly a threat actor category; specific enough for "
                     "T1078 (valid accounts) and T1657 (financial theft) but requires judgment"
    },
    "B-009": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly describes MSSP compromise as pivot (T1199 trusted relationship); "
                     "specific third-party attack vector with named entity type"
    },
    "B-011": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: describes ATM processor compromise with lateral movement to core banking; "
                     "specific attack chain via trusted relationship (T1199) and lateral movement"
    },
    "B-012": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly describes vendor VPN exploitation (T1133 external remote services, "
                     "T1199 trusted relationship); specific attack vector"
    },
    "B-013": {
        "ambiguity_class": "clear_match",
        "rationale": "GP3: explicitly names spearphishing (T1566), M365 exploitation, and BEC against "
                     "treasury; multi-technique scenario with concrete behaviors"
    },
    "B-014": {
        "ambiguity_class": "plausible_match",
        "rationale": "GP3/GP5: describes cloud misconfiguration exploitation during migration; "
                     "'misconfiguration' is a condition rather than a specific ATT&CK behavior, "
                     "but implies T1078 (valid accounts) or discovery techniques; requires judgment"
    },
}


def classify_baseline(baseline_path):
    """Classify baseline LLM outputs using pre-populated behavioral analysis.

    Baseline scenarios are narrative attack descriptions without technique IDs.
    Classification is based on whether the narrative describes explicit or strongly
    implied ATT&CK-level behaviors (GP3) or is too vague (GP5).
    """
    results = []

    with open(baseline_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("included", "0").strip() != "1":
                continue

            threat_id = row["threat_id"].strip()
            description = row["threat_description"].strip()

            if threat_id in BASELINE_CLASSIFICATIONS:
                classification = BASELINE_CLASSIFICATIONS[threat_id]
                results.append({
                    "threat_id": threat_id,
                    "technique_id": "",
                    "threat_description": description,
                    "ambiguity_class": classification["ambiguity_class"],
                    "rationale": classification["rationale"],
                })
            else:
                # Fallback for any unexpected included baseline items
                results.append({
                    "threat_id": threat_id,
                    "technique_id": "",
                    "threat_description": description,
                    "ambiguity_class": "plausible_match",
                    "rationale": "GP3: not pre-classified; requires researcher review",
                })

    return results


def write_classification(results, output_path, dry_run=False):
    """Write classification results to CSV."""
    fieldnames = ["threat_id", "technique_id", "threat_description",
                  "ambiguity_class", "rationale"]

    if dry_run:
        print(f"\n[DRY RUN] Would write {len(results)} rows to {output_path}")
        return

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Wrote {len(results)} rows to {output_path}")


def print_summary(results, label):
    """Print distribution of ambiguity classes."""
    counts = {}
    for r in results:
        cls = r["ambiguity_class"]
        counts[cls] = counts.get(cls, 0) + 1

    print(f"\n=== {label} ===")
    print(f"  Total items: {len(results)}")
    for cls in ["clear_match", "plausible_match", "no_match"]:
        print(f"  {cls}: {counts.get(cls, 0)}")


def main():
    parser = argparse.ArgumentParser(
        description="Story 2.4: Classify LLM output ambiguity for ATT&CK mapping"
    )
    parser.add_argument(
        "--attck-matrix",
        default="data/attck-coding-matrix.csv",
        help="Path to ATT&CK v15 coding matrix CSV (default: data/attck-coding-matrix.csv)"
    )
    parser.add_argument(
        "--structured-input",
        default="data/llm/structured/consolidated.csv",
        help="Path to structured consolidated CSV (default: data/llm/structured/consolidated.csv)"
    )
    parser.add_argument(
        "--baseline-input",
        default="data/llm/baseline/consolidated.csv",
        help="Path to baseline consolidated CSV (default: data/llm/baseline/consolidated.csv)"
    )
    parser.add_argument(
        "--structured-output",
        default="data/llm/structured/ambiguity-classification.csv",
        help="Output path for structured classification"
    )
    parser.add_argument(
        "--baseline-output",
        default="data/llm/baseline/ambiguity-classification.csv",
        help="Output path for baseline classification"
    )
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="Skip baseline classification (for non-Claude providers with structured only)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary without writing output files"
    )
    args = parser.parse_args()

    # Validate input files exist
    required_files = [(args.attck_matrix, "ATT&CK matrix")]
    required_files.append((args.structured_input, "Structured consolidated"))
    if not args.skip_baseline:
        required_files.append((args.baseline_input, "Baseline consolidated"))

    for path, label in required_files:
        if not os.path.isfile(path):
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    # Load ATT&CK technique lookup
    attck_lookup = load_attck_matrix(args.attck_matrix)
    print(f"Loaded {len(attck_lookup)} unique techniques from ATT&CK v15 matrix")

    # Classify structured variant (automated EC5 cross-reference)
    structured_results = classify_structured(args.structured_input, attck_lookup)
    print_summary(structured_results, "Structured Variant")
    write_classification(structured_results, args.structured_output, args.dry_run)

    # Classify baseline variant (pre-populated behavioral analysis)
    if not args.skip_baseline:
        baseline_results = classify_baseline(args.baseline_input)
        print_summary(baseline_results, "Baseline Variant")
        write_classification(baseline_results, args.baseline_output, args.dry_run)
    else:
        print("\n  Skipping baseline classification (--skip-baseline)")

    if args.dry_run:
        print("\n[DRY RUN] No files written. Remove --dry-run to write output files.")
    else:
        print("\nClassification complete. Researcher should review output files before coding.")


if __name__ == "__main__":
    main()
