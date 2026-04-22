#!/usr/bin/env python3
"""
Package Manual LLM Runs (Web Interface Workflow)

Converts manually saved LLM responses (from claude.ai web interface) into the
standardized JSON format expected by consolidate-runs.py.

Workflow:
    1. Run each prompt on claude.ai in a NEW conversation (no history).
    2. Copy the full response and save as a .txt file.
    3. Use this script to package into the expected JSON format.

Expected input file naming:
    data/llm/baseline/response-1.txt
    data/llm/baseline/response-2.txt
    data/llm/baseline/response-3.txt
    data/llm/structured/response-1.txt
    data/llm/structured/response-2.txt
    data/llm/structured/response-3.txt

Usage:
    python package-manual-runs.py --variant baseline --input-dir data/llm/baseline
    python package-manual-runs.py --variant structured --input-dir data/llm/structured
    python package-manual-runs.py --variant baseline --input-dir data/llm/baseline --dry-run
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Package manually saved LLM responses into standardized JSON."
    )
    parser.add_argument(
        "--variant",
        type=str,
        required=True,
        choices=["baseline", "structured"],
        help="Prompt variant.",
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        required=True,
        help="Directory containing response-*.txt files.",
    )
    parser.add_argument(
        "--prompt-file",
        type=str,
        default=None,
        help="Path to the prompt text file (auto-detected if not specified).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="claude-sonnet-4-20250514",
        help="Model used on web interface (default: claude-sonnet-4-20250514).",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Temperature (note: web interface uses default, record as 0.7).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be packaged without writing.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Directory not found: {args.input_dir}")
        sys.exit(1)

    # Find response files
    response_files = sorted(input_dir.glob("response-*.txt"))
    if not response_files:
        print(f"Error: No response-*.txt files found in {args.input_dir}")
        print(f"\nExpected files:")
        print(f"  {input_dir}/response-1.txt")
        print(f"  {input_dir}/response-2.txt")
        print(f"  {input_dir}/response-3.txt")
        sys.exit(1)

    # Load prompt
    prompt_file = args.prompt_file
    if not prompt_file:
        prompt_file = str(input_dir.parent / f"prompt-{args.variant}.txt")

    prompt_path = Path(prompt_file)
    if not prompt_path.exists():
        print(f"Error: Prompt file not found: {prompt_file}")
        sys.exit(1)

    prompt_text = prompt_path.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

    print(f"Variant:       {args.variant}")
    print(f"Prompt file:   {prompt_file} ({len(prompt_text)} chars)")
    print(f"Prompt hash:   {prompt_hash[:16]}...")
    print(f"Response files: {len(response_files)} found")
    print()

    for rf in response_files:
        # Extract run number from filename (response-1.txt -> 1)
        run_num = int(rf.stem.split("-")[1])
        response_text = rf.read_text(encoding="utf-8")

        print(f"  response-{run_num}.txt: {len(response_text)} chars")

        artifact = {
            "metadata": {
                "variant": args.variant,
                "run_number": run_num,
                "model": args.model,
                "temperature": args.temperature,
                "max_tokens": 4096,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prompt_hash": prompt_hash,
                "api_response_id": f"manual-web-run-{run_num}",
                "collection_method": "manual-web-interface",
            },
            "prompt": prompt_text,
            "response": response_text,
            "usage": {
                "input_tokens": None,
                "output_tokens": None,
            },
        }

        output_file = input_dir / f"run-{run_num}.json"

        if args.dry_run:
            print(f"    [DRY RUN] Would write: {output_file}")
        else:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(artifact, f, indent=2, ensure_ascii=False)
            print(f"    Packaged -> {output_file}")

    if args.dry_run:
        print(f"\n[DRY RUN] No files written.")
    else:
        print(f"\nDone. {len(response_files)} runs packaged in: {args.input_dir}")
        print(f"Next step: python scripts/consolidate-runs.py --input-dir {args.input_dir}")


if __name__ == "__main__":
    main()
