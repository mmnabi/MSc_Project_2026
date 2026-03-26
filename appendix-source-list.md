# Appendix C: Bounded Source List for Traditional Method

---

## Purpose

This document defines the finite, pre-determined list of publicly available threat intelligence sources consulted during the traditional (ISO 27005) threat identification exercise. The list is fixed before execution begins. The traditional method's scope is bounded by this list -- enumeration ends when all sources have been systematically consulted, not when the researcher subjectively feels "done."

---

## Stopping Criterion

Threat identification for the traditional method is complete when:
1. Every source listed below has been consulted and documented.
2. Every threat identified from these sources that is relevant to the synthetic organizational profile (Appendix A) has been recorded in the threat inventory.
3. No additional sources beyond this list have been introduced.

---

## Source List

### 1. ENISA Threat Landscape Report (2024)

- **Full title:** ENISA Threat Landscape 2024
- **Publisher:** European Union Agency for Cybersecurity (ENISA)
- **Usage:** Primary source for current threat landscape affecting European organizations. Extract top threats, threat actor trends, and attack vector analysis relevant to financial services.

### 2. FS-ISAC Public Threat Advisories

- **Full title:** FS-ISAC Navigating Cyber Reports and Public Advisories (2024--2025)
- **Publisher:** Financial Services Information Sharing and Analysis Center
- **Usage:** Financial-sector-specific threat intelligence. Extract threats, campaigns, and TTPs specifically targeting financial institutions.

### 3. MITRE ATT&CK Threat Group Profiles -- Financial Services

Consult the following threat groups known to target financial services:

| Group | ATT&CK ID | Primary Target |
|---|---|---|
| FIN7 | G0046 | Financial services, retail |
| Carbanak (FIN7-related) | G0008 | Banking, financial |
| Lazarus Group | G0032 | Financial (SWIFT), crypto |
| APT38 | G0082 | Financial institutions (SWIFT) |
| TA505 | G0092 | Financial, retail |

- **Version:** ATT&CK Enterprise v15 (version-locked)
- **Usage:** Extract documented techniques, tactics, and software used by each group. Cross-reference with organizational profile to assess relevance.

### 4. Europol Internet Organised Crime Threat Assessment (IOCTA 2024)

- **Full title:** Internet Organised Crime Threat Assessment 2024
- **Publisher:** Europol -- European Union Agency for Law Enforcement Cooperation
- **Usage:** Supplement ENISA with law enforcement perspective on organized cybercrime trends affecting financial sector, including fraud schemes, ransomware operations, and money laundering-related cyber activity.

### 5. CISA Known Exploited Vulnerabilities (KEV) Catalog -- Financial Sector Subset

- **Full title:** CISA Known Exploited Vulnerabilities Catalog
- **Publisher:** Cybersecurity and Infrastructure Security Agency (CISA)
- **Usage:** Identify actively exploited vulnerabilities relevant to the organization's technology stack (Windows, Azure, .NET, Oracle DB, Palo Alto, Cisco). Map to threat categories and associated ATT&CK techniques where documented.

### 6. SWIFT Customer Security Programme -- Threat Intelligence Updates

- **Full title:** SWIFT ISAC Cyber Threat Intelligence Reports (public summaries)
- **Publisher:** SWIFT
- **Usage:** Threats specifically targeting SWIFT infrastructure and interbank messaging. Critical for the organizational profile given SWIFT connectivity.

---

## Source Exclusions

The following types of sources are explicitly **not** consulted to maintain scope boundaries:

- Paid/commercial threat intelligence feeds (not available within project constraints).
- Dark web monitoring or paste site data.
- Social media OSINT.
- Vendor-specific threat reports (e.g., CrowdStrike, Microsoft, Palo Alto annual reports) -- to avoid overlap with sources that may be in the LLM's training data.
- Academic papers on threat landscapes (these inform the literature review, not the threat identification exercise itself).

---

## Documentation Requirements

For each source consulted, the researcher must record:
1. **Date accessed**
2. **Specific sections/pages consulted**
3. **Number of threats extracted**
4. **Any relevance filtering decisions** (threats identified in source but excluded as not relevant to the org profile, with brief rationale)

---

*This source list is frozen as of the date it is finalized. No additions or substitutions are permitted during execution without documenting the change and rationale.*
