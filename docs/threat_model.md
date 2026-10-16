# LockSentry AI — Threat Model & Security Boundaries

## 1. System Scope & Assets Under Protection

LockSentry AI operates as an automated pre-merge dependency security gate.
The primary assets under protection are:
1. **Software Supply Chain Integrity**: Preventing the introduction of vulnerable, malicious, downgraded, or unverified third-party libraries into application repositories.
2. **Developer Environment Safety**: Ensuring that untrusted dependency files submitted for scanning cannot trigger arbitrary remote code execution during analysis.
3. **Decision Authenticity**: Ensuring that AI models cannot be coerced or manipulated into overruling deterministic security policies.
4. **Data Privacy**: Guaranteeing that internal dependency manifests are not leaked to external third-party hosted model providers.

---

## 2. Trust Boundaries & Assumptions

- **Untrusted Inputs**: Dependency manifests (`requirements.txt`, `package-lock.json`) are treated as completely untrusted input. They may be malformed, contain malicious characters, or reference malicious package names.
- **External Intelligence (OSV.dev)**: The Google OSV API is a trusted intelligence source for known public vulnerabilities, but its completeness is bounded. Absence of an advisory does NOT prove that a library is safe.
- **AI Model Runtime**: Local open-weight models (Ollama `gemma2:2b`) are treated as advisory components. Their outputs are untrusted until validated against Pydantic schemas and cross-referenced with input evidence.
- **Host Execution Environment**: The host environment running LockSentry AI must never execute package code or run `pip install` / `npm install` on user-submitted files.

---

## 3. Threat Analysis (STRIDE Matrix)

| STRIDE Category | Threat Description | Attack Vector | Mitigations in LockSentry AI |
|---|---|---|---|
| **Spoofing** | Typosquatting / Package Identity Confusion | Attacker submits a package name mimicking an authentic library (e.g. `reqeusts` vs `requests`). | Exact package normalization and OSV database querying. Non-existent packages return `NO_KNOWN_ADVISORY` but trigger unpinned/ambiguity checks if versions are uncertain. |
| **Tampering** | Malicious Lockfile Manipulation | Attacker modifies hashes, introduces malicious transitive dependencies, or downgrades secure packages to vulnerable versions. | SemVer differential analysis detects `DOWNGRADED` packages and automatically triggers a deterministic `BLOCK`. |
| **Repudiation** | Lack of Audit Accountability | Developer bypasses security gate without leaving an audit trail. | Comprehensive, immutable audit reports generated in both JSON (`locksentry_report.json`) and Markdown formats with timestamps, evidence citations, and decision rationales. |
| **Information Disclosure** | Leakage of Internal Dependencies | Manifests containing proprietary internal package names or credentials submitted to hosted AI APIs. | **Local Open-Weight Inference**: Uses local Ollama runtime (`gemma2:2b` or `llama3:latest`) on `localhost:11434`. No proprietary manifest data or file contents are sent to external LLM APIs. |
| **Denial of Service** | Resource Exhaustion via Malformed Files | Attacker submits multi-megabyte malformed manifests or deeply nested lockfiles to cause CPU/memory starvation. | File size limits, defensive regex parsing with linear complexity, strict HTTP request timeouts (10s on OSV API), and non-blocking background task management. |
| **Elevation of Privilege** | Remote Code Execution via Install Scripts | Attacker includes executable scripts (`setup.py`, npm lifecycle hooks) in dependency files. | **Strict Static Analysis**: LockSentry AI parses manifest tokens purely as static text and JSON structures. It NEVER executes `setup.py`, `npm install`, or subprocess shell commands on dependencies. |

---

## 4. AI-Specific Risks & Countermeasures

### Threat: Model Sycophancy & Hallucinated Safety
- **Risk**: An LLM might be prompted to declare a vulnerable package "safe for this context" or hallucinate non-existent CVEs and remediation versions.
- **Countermeasures**:
  1. **Strict Deterministic Precedence**: The deterministic policy engine produces gate decisions (`PASS`, `BLOCK`, `REVIEW`) independently of the model. The model has zero programmatic authority to modify the gate outcome.
  2. **Automated Evidence Grounding Verification**: A post-generation verification algorithm inspects every package and CVE mentioned in the AI report. Any hallucinated CVE or unverified package triggers a grounding violation flag (`grounding_verified = False`).
  3. **Low Temperature Inference**: Model inference is configured with `temperature: 0.2` to enforce deterministic, factual reasoning.

### Threat: Model Failure / Offline DoS
- **Risk**: If the local Ollama daemon crashes or times out, the gate could crash or fail open.
- **Countermeasures**:
  - The `OpenWeightAIAnalyzer` incorporates an automatic **Deterministic Fallback Engine**. If Ollama is offline or fails schema validation, the gate continues operating deterministically using OSV rules, explicitly marking the report as `[FALLBACK MODE: AI offline]`.

---

## 5. Documented Limitations & Threat Boundaries

1. **Zero-Day Vulnerabilities**: LockSentry AI queries public vulnerability databases (OSV, CVE, GHSA). It cannot identify previously undisclosed zero-day exploits in newly released package versions.
2. **Floating Constraints**: Manifests specifying wildcards (`*`) or unbounded ranges (`>=1.0`) cannot be reliably certified without a lockfile. Such dependencies are intentionally flagged as `REVIEW` rather than assumed safe.
3. **Malicious Package Intent**: A package with malicious intent that has not yet been assigned a public CVE will not be caught solely by OSV vulnerability lookups. Static analysis should be complemented with behavioral sandbox scanners.
