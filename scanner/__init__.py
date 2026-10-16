"""LockSentry AI Scanner Package.

Core modules:
- dependency_parser: Manifest and lockfile parsing (requirements.txt, package-lock.json)
- osv_client: Official OSV.dev vulnerability database client
- policy_engine: Deterministic security gate (PASS / BLOCK / REVIEW)
- ai_analyzer: Open-weight LLM reasoning and trade-off evaluator
- report_generator: Structured JSON & Markdown audit reports
"""

__version__ = "0.1.0"
