# Appendix D: LLM Prompt Protocol and Verbatim Prompts

---

## Execution Parameters

| Parameter | Value |
|---|---|
| **Model** | claude-sonnet-4-20250514 |
| **Temperature** | 0.7 |
| **Max tokens** | 4,096 |
| **Top-p** | 1.0 (default) |
| **Runs per variant** | 3 |
| **Total runs** | 6 (3 baseline + 3 structured) |
| **Message history** | None -- each run is a fresh, single-turn conversation |
| **System prompt** | None |

---

## Prompt Variant 1: Baseline

**Design intent:** Provide the organizational profile and request threat identification without referencing any specific framework or taxonomy. The LLM uses its general knowledge to identify relevant threats.

### Verbatim Prompt Text

```
You are a cybersecurity consultant performing a threat identification exercise for a client organization. Based on the organizational profile provided below, identify the most relevant cyber threats facing this organization.

For each threat you identify:
1. Provide a clear, specific threat description (not generic categories).
2. Explain why this threat is relevant to this specific organization.
3. Describe the likely attack vector or method.
4. Assess the potential impact on the organization.

Be comprehensive and specific. Focus on threats that are realistic and relevant given the organization's industry, size, infrastructure, and security posture.

---

ORGANIZATIONAL PROFILE:

[FULL TEXT OF ORGANIZATIONAL PROFILE INSERTED HERE -- see Appendix A]
```

**Notes:**
- The placeholder is replaced with the complete, verbatim text of the organizational profile at execution time.
- No reference to MITRE ATT&CK, ISO 27005, or any other specific framework.
- The prompt asks for threat *descriptions* and *methods*, providing material that can be mapped to ATT&CK post-hoc.

---

## Prompt Variant 2: Structured (ATT&CK-Referenced)

**Design intent:** Provide the organizational profile and explicitly reference MITRE ATT&CK, requesting output organized by tactic. This tests whether explicit framework framing changes coverage breadth, depth, or quality.

### Verbatim Prompt Text

```
You are a cybersecurity consultant performing a threat identification exercise for a client organization using the MITRE ATT&CK Enterprise framework as your analytical lens.

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

[FULL TEXT OF ORGANIZATIONAL PROFILE INSERTED HERE -- see Appendix A]
```

**Notes:**
- Same organizational profile insertion as baseline variant.
- Explicitly names all 14 ATT&CK tactics to encourage breadth.
- Asks for technique IDs, but these must be verified during coding (see mapping decision rule EC5 in Appendix B).

---

## Consolidation Rule

For each prompt variant, the three run outputs are consolidated into a single inventory using a **union rule with a 2-of-3 threshold:**

- A threat/technique is included in the consolidated inventory if it appears in **at least 2 of the 3 runs** for that variant.
- "Appears" means the same substantive threat is described, even if wording differs across runs. Matching is based on researcher judgment of semantic equivalence, not string matching.
- Threats appearing in only 1 of 3 runs are documented but excluded from the consolidated inventory.

This rule balances inclusivity (not discarding valid threats due to stochastic variation) with reliability (filtering out one-off artifacts).

---

## Output Handling

### Per-Run Artifacts
Each run is saved as a JSON file with the following structure:

```json
{
  "metadata": {
    "variant": "baseline | structured",
    "run_number": "1 | 2 | 3",
    "model": "claude-sonnet-4-20250514",
    "temperature": 0.7,
    "max_tokens": 4096,
    "timestamp": "ISO 8601 timestamp",
    "prompt_hash": "SHA-256 hash of the prompt text",
    "api_response_id": "Anthropic API response ID"
  },
  "prompt": "Full prompt text used",
  "response": "Full LLM response text",
  "usage": {
    "input_tokens": 0,
    "output_tokens": 0
  }
}
```

### Consolidated Artifacts
Each variant's consolidated output is saved as a CSV with columns:

```csv
threat_id,threat_description,attack_vector,relevance,run_1,run_2,run_3,included
```

- `threat_id`: Sequential identifier (B-001 for baseline, S-001 for structured).
- `run_1`, `run_2`, `run_3`: 1 if the threat appeared in that run, 0 if not.
- `included`: 1 if the threat meets the 2-of-3 threshold, 0 if not.

---

*All prompts in this document are frozen as of the date this document is finalized. No modifications are permitted after the first execution run begins.*
