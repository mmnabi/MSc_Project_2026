#!/usr/bin/env python3
"""
LLM Threat Identification Runner (Stories 2.2, 2.3)

Runs LLM API prompts with controlled parameters for the LLM-based threat
identification method. Supports multiple providers (Claude, Gemini, OpenAI).
Each run is a fresh, single-turn conversation with no message history
carried between runs.

Usage:
    python llm-runner.py --provider claude --variant structured --runs 3 --output-dir data/llm/structured
    python llm-runner.py --provider gemini --variant structured --runs 3 --output-dir data/llm/gemini-structured
    python llm-runner.py --provider openai --variant structured --runs 3 --output-dir data/llm/openai-structured
    python llm-runner.py --provider claude --variant baseline --runs 3 --output-dir data/llm/baseline
    python llm-runner.py --variant structured --runs 1 --dry-run

Requires:
    - API key environment variable set for the chosen provider:
      ANTHROPIC_API_KEY (Claude), GOOGLE_API_KEY or GEMINI_API_KEY (Gemini),
      OPENAI_API_KEY (OpenAI)
    - docs/org-profile.md (organizational profile)
    - docs/prompt-protocol.md (for reference -- prompts are embedded here)
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Default execution parameters (from prompt-protocol.md)
DEFAULT_MODELS = {
    "claude": "claude-sonnet-4-20250514",
    "gemini": "gemini-2.5-pro",
    "openai": "gpt-4o-2024-11-20",
}
DEFAULT_TEMPERATURE = 0.7
DEFAULT_MAX_TOKENS = 4096
DEFAULT_RUNS = 3


def load_org_profile(profile_path: str) -> str:
    """Load the organizational profile text."""
    path = Path(profile_path)
    if not path.exists():
        print(f"Error: Organizational profile not found at: {profile_path}")
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def build_prompt(variant: str, org_profile: str) -> str:
    """
    Build the full prompt for a given variant.

    Prompts are defined in docs/prompt-protocol.md and embedded here
    for execution. The same prompt text is sent to all providers.
    """
    if variant == "baseline":
        return f"""You are a cybersecurity consultant performing a threat identification exercise for a client organization. Based on the organizational profile provided below, identify the most relevant cyber threats facing this organization.

For each threat you identify:
1. Provide a clear, specific threat description (not generic categories).
2. Explain why this threat is relevant to this specific organization.
3. Describe the likely attack vector or method.
4. Assess the potential impact on the organization.

Be comprehensive and specific. Focus on threats that are realistic and relevant given the organization's industry, size, infrastructure, and security posture.

---

ORGANIZATIONAL PROFILE:

{org_profile}"""

    elif variant == "structured":
        return f"""You are a cybersecurity consultant performing a threat identification exercise for a client organization using the MITRE ATT&CK Enterprise framework as your analytical lens.

Based on the organizational profile provided below, identify relevant cyber threats mapped to the MITRE ATT&CK Enterprise framework.

Organize your analysis by the 14 ATT&CK Enterprise tactics:
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

For each tactic:
- Identify specific ATT&CK techniques that are relevant threats to this organization.
- For each technique, explain why it is relevant given the organization's specific infrastructure, services, and security posture.
- Provide the ATT&CK technique ID and name where possible.

Be comprehensive. Consider threats across all 14 tactics, not just the most common ones.

---

ORGANIZATIONAL PROFILE:

{org_profile}"""

    else:
        print(f"Error: Unknown variant '{variant}'. Use 'baseline' or 'structured'.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Provider-specific run functions
# ---------------------------------------------------------------------------

def _run_claude(prompt, model, temperature, max_tokens, max_retries, run_number):
    """Execute a single run using the Anthropic Claude API."""
    try:
        import anthropic
    except ImportError:
        print("Error: 'anthropic' package required. Install with: pip install anthropic")
        sys.exit(1)

    client = anthropic.Anthropic()  # Uses ANTHROPIC_API_KEY

    for attempt in range(1, max_retries + 1):
        try:
            print(f"  Run {run_number}: Calling Claude API (attempt {attempt})...")
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = ""
            for block in response.content:
                if block.type == "text":
                    response_text += block.text

            return {
                "response_text": response_text,
                "response_id": response.id,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }

        except anthropic.APIStatusError as e:
            if attempt < max_retries and e.status_code in (429, 500, 502, 503, 529):
                wait = 2 ** attempt
                print(f"  Run {run_number}: API error ({e.status_code}), retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise


def _run_gemini(prompt, model, temperature, max_tokens, max_retries, run_number):
    """Execute a single run using the Google Gemini API."""
    try:
        import google.generativeai as genai
    except ImportError:
        print("Error: 'google-generativeai' package required. Install with: pip install google-generativeai")
        sys.exit(1)

    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: Set GOOGLE_API_KEY or GEMINI_API_KEY environment variable.")
        sys.exit(1)

    genai.configure(api_key=api_key)
    gen_model = genai.GenerativeModel(model)

    for attempt in range(1, max_retries + 1):
        try:
            print(f"  Run {run_number}: Calling Gemini API (attempt {attempt})...")
            response = gen_model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )

            response_text = response.text

            # Extract token usage
            usage = response.usage_metadata
            input_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
            output_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0

            return {
                "response_text": response_text,
                "response_id": f"gemini-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }

        except Exception as e:
            error_str = str(e)
            is_transient = any(
                kw in error_str.lower()
                for kw in ["429", "500", "503", "rate", "quota", "overloaded", "unavailable"]
            )
            if attempt < max_retries and is_transient:
                wait = 2 ** attempt
                print(f"  Run {run_number}: Gemini API error, retrying in {wait}s... ({error_str[:80]})")
                time.sleep(wait)
            else:
                raise


def _run_openai(prompt, model, temperature, max_tokens, max_retries, run_number):
    """Execute a single run using the OpenAI API."""
    try:
        from openai import OpenAI
        import openai as openai_module
    except ImportError:
        print("Error: 'openai' package required. Install with: pip install openai")
        sys.exit(1)

    client = OpenAI()  # Uses OPENAI_API_KEY

    for attempt in range(1, max_retries + 1):
        try:
            print(f"  Run {run_number}: Calling OpenAI API (attempt {attempt})...")
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )

            response_text = response.choices[0].message.content or ""

            return {
                "response_text": response_text,
                "response_id": response.id,
                "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                "output_tokens": response.usage.completion_tokens if response.usage else 0,
            }

        except openai_module.APIStatusError as e:
            if attempt < max_retries and e.status_code in (429, 500, 502, 503):
                wait = 2 ** attempt
                print(f"  Run {run_number}: OpenAI API error ({e.status_code}), retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise


# Provider dispatch
PROVIDER_RUNNERS = {
    "claude": _run_claude,
    "gemini": _run_gemini,
    "openai": _run_openai,
}


def run_single(
    provider: str,
    prompt: str,
    model: str,
    temperature: float,
    max_tokens: int,
    variant: str,
    run_number: int,
    max_retries: int = 3,
) -> dict:
    """
    Execute a single LLM run and return the full artifact.

    Each run is a fresh conversation -- no message history is carried.
    Dispatches to provider-specific implementation.
    """
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    runner = PROVIDER_RUNNERS[provider]
    result = runner(prompt, model, temperature, max_tokens, max_retries, run_number)

    artifact = {
        "metadata": {
            "provider": provider,
            "variant": variant,
            "run_number": run_number,
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt_hash": prompt_hash,
            "api_response_id": result["response_id"],
        },
        "prompt": prompt,
        "response": result["response_text"],
        "usage": {
            "input_tokens": result["input_tokens"],
            "output_tokens": result["output_tokens"],
        },
    }

    print(
        f"  Run {run_number}: Complete. "
        f"Input: {result['input_tokens']} tokens, "
        f"Output: {result['output_tokens']} tokens."
    )
    return artifact


def main():
    parser = argparse.ArgumentParser(
        description="Run LLM-based threat identification with controlled parameters."
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="claude",
        choices=["claude", "gemini", "openai"],
        help="LLM provider to use (default: claude).",
    )
    parser.add_argument(
        "--variant",
        type=str,
        required=True,
        choices=["baseline", "structured"],
        help="Prompt variant to execute.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Number of runs (default: {DEFAULT_RUNS}).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Output directory for run artifacts (e.g., data/llm/gemini-structured).",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default="docs/org-profile.md",
        help="Path to organizational profile (default: docs/org-profile.md).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model to use (default: provider-specific, see --help for defaults).",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=DEFAULT_TEMPERATURE,
        help=f"Temperature setting (default: {DEFAULT_TEMPERATURE}).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Max output tokens (default: {DEFAULT_MAX_TOKENS}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build prompt and show parameters without calling the API.",
    )
    args = parser.parse_args()

    # Resolve default model for the chosen provider
    model = args.model or DEFAULT_MODELS[args.provider]

    # Load organizational profile
    org_profile = load_org_profile(args.profile)
    print(f"Loaded organizational profile: {args.profile} ({len(org_profile)} chars)")

    # Build prompt
    prompt = build_prompt(args.variant, org_profile)
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

    print(f"\nExecution parameters:")
    print(f"  Provider:    {args.provider}")
    print(f"  Variant:     {args.variant}")
    print(f"  Model:       {model}")
    print(f"  Temperature: {args.temperature}")
    print(f"  Max tokens:  {args.max_tokens}")
    print(f"  Runs:        {args.runs}")
    print(f"  Prompt hash: {prompt_hash}...")
    print(f"  Output dir:  {args.output_dir}")

    if args.dry_run:
        print(f"\n[DRY RUN] Would execute {args.runs} runs.")
        print(f"\nPrompt preview (first 500 chars):")
        print("-" * 60)
        print(prompt[:500])
        print("-" * 60)
        return

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Execute runs
    print(f"\nStarting {args.runs} runs...\n")
    for run_num in range(1, args.runs + 1):
        artifact = run_single(
            provider=args.provider,
            prompt=prompt,
            model=model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            variant=args.variant,
            run_number=run_num,
        )

        # Save artifact
        output_file = output_dir / f"run-{run_num}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(artifact, f, indent=2, ensure_ascii=False)
        print(f"  Saved: {output_file}\n")

        # Save plain text response alongside JSON
        response_file = output_dir / f"response-{run_num}.txt"
        with open(response_file, "w", encoding="utf-8") as f:
            f.write(artifact["response"])
        print(f"  Saved: {response_file}\n")

        # Brief pause between runs to avoid rate limiting
        if run_num < args.runs:
            time.sleep(2)

    print(f"All {args.runs} runs complete. Outputs in: {args.output_dir}")


if __name__ == "__main__":
    main()
