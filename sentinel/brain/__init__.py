"""Sentinel AI brain (§5) — bounded-role LLM integration.

Public surface:
    SafeInput        — §5 SAFE INPUT SCHEMA record (the ONLY outbound shape)
    build_safe_input — single choke point serializing ALL outbound prompts
    render_prompt    — stable JSON rendering of a SafeInput (audit-verbatim)
    BrainOutputError — raised on any schema violation in LLM output
    TriageResult     — validated LLM classification (advisory only)
    parse_output     — JSON-schema-only validator for raw LLM text
    LLMClient        — injectable HTTP wrapper (temp 0–0.2, 8s/5s deadlines)
    PromptResponsePair — frozen/hashable/replayable audit record (G7/P6)
    triage_incident  — orchestrator; NEVER raises (P4 silent fallback)

The LLM never issues commands and is never the final authority: its output
is schema-validated, then consumed by the deterministic Decision Engine via
the existing severity_override seam. Invalid/timeout/failure ⇒ rule-based
path continues silently with no error leak.
"""
from __future__ import annotations

from sentinel.brain.audit import PromptResponsePair
from sentinel.brain.client import LLMClient
from sentinel.brain.output import BrainOutputError, TriageResult, parse_output
from sentinel.brain.schema import SafeInput, build_safe_input, render_prompt
from sentinel.brain.triage import triage_incident

__all__ = [
    "SafeInput",
    "build_safe_input",
    "render_prompt",
    "BrainOutputError",
    "TriageResult",
    "parse_output",
    "LLMClient",
    "PromptResponsePair",
    "triage_incident",
]
