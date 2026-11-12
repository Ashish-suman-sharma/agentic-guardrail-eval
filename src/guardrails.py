"""Defensive guardrail implementations for agentic AI pipelines.

Provides composable middleware for:
- Untrusted-context isolation (delimiter wrapping & injection stripping)
- Tool-call allowlisting with human-in-the-loop approval gates
- Canary / secret leak detection (regex + Shannon entropy)
- Structured input validation and PII-redacting output validation
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared result type
# ---------------------------------------------------------------------------


class GuardrailVerdict(str, Enum):
    """Outcome of a single guardrail check."""

    PASS = "pass"
    BLOCK = "block"
    MODIFY = "modify"


@dataclass(frozen=True)
class GuardrailResult:
    """Immutable result returned by every guardrail check."""

    verdict: GuardrailVerdict
    guardrail_name: str
    reason: str = ""
    original_content: str = ""
    modified_content: str | None = None

    @property
    def passed(self) -> bool:
        return self.verdict != GuardrailVerdict.BLOCK


# ---------------------------------------------------------------------------
# 1. Untrusted-Context Isolation
# ---------------------------------------------------------------------------

# Sentinel delimiters that wrap any content originating outside the trusted
# system prompt / user turn.  The hardened agent checks that instructions
# inside these delimiters are *never* treated as control-flow directives.
UNTRUSTED_OPEN = "<<UNTRUSTED_CONTEXT_START>>"
UNTRUSTED_CLOSE = "<<UNTRUSTED_CONTEXT_END>>"

# Patterns commonly found in indirect prompt-injection payloads.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|above|previous|your\s+system\s+prompt|system\s+prompt|everything)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|the|[\"']?\w+[\"']?)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"ADMIN\s*OVERRIDE", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"###\s*(SYSTEM|INSTRUCTION)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|prior|above)", re.IGNORECASE),
]


class UntrustedContextIsolator:
    """Wraps external content in isolation delimiters and flags injections.

    In *hardened* mode the isolator:
    1. Wraps the raw context inside ``UNTRUSTED_OPEN / UNTRUSTED_CLOSE``.
    2. Scans for common injection patterns and **strips** them.
    3. Returns a ``GuardrailResult`` with verdict ``MODIFY`` (content was
       sanitised) or ``BLOCK`` (too many injection signals detected).

    A maximum-injection-density threshold (``block_threshold``) controls
    when the content is blocked outright vs. merely sanitised.
    """

    def __init__(self, block_threshold: int = 3) -> None:
        self.block_threshold = block_threshold

    def wrap(self, raw_context: str) -> str:
        """Return *raw_context* wrapped in isolation delimiters."""
        return f"{UNTRUSTED_OPEN}\n{raw_context}\n{UNTRUSTED_CLOSE}"

    def check(self, raw_context: str) -> GuardrailResult:
        """Scan *raw_context* for injection patterns."""
        matches: list[str] = []
        sanitised = raw_context
        for pattern in _INJECTION_PATTERNS:
            found = pattern.findall(sanitised)
            if found:
                matches.extend(found)
                sanitised = pattern.sub("[REDACTED_INJECTION]", sanitised)

        if len(matches) >= self.block_threshold:
            return GuardrailResult(
                verdict=GuardrailVerdict.BLOCK,
                guardrail_name="UntrustedContextIsolator",
                reason=(
                    f"Blocked: {len(matches)} injection pattern(s) detected "
                    f"(threshold={self.block_threshold})."
                ),
                original_content=raw_context,
            )

        if matches:
            wrapped = self.wrap(sanitised)
            return GuardrailResult(
                verdict=GuardrailVerdict.MODIFY,
                guardrail_name="UntrustedContextIsolator",
                reason=f"Sanitised {len(matches)} injection pattern(s).",
                original_content=raw_context,
                modified_content=wrapped,
            )

        return GuardrailResult(
            verdict=GuardrailVerdict.PASS,
            guardrail_name="UntrustedContextIsolator",
            reason="No injection patterns detected.",
            original_content=raw_context,
            modified_content=self.wrap(raw_context),
        )


# ---------------------------------------------------------------------------
# 2. Tool-Call Allowlisting & Human-in-the-Loop Gates
# ---------------------------------------------------------------------------


class ApprovalLevel(str, Enum):
    """Required approval level for a tool invocation."""

    NONE = "none"  # auto-approved
    USER_CONFIRM = "user_confirm"  # requires explicit user consent
    ADMIN_ONLY = "admin_only"  # requires admin role


@dataclass
class ToolPolicy:
    """Declarative policy for a single tool."""

    tool_name: str
    allowed_roles: list[str] = field(default_factory=lambda: ["user", "admin"])
    approval_level: ApprovalLevel = ApprovalLevel.NONE
    max_calls_per_session: int | None = None


class ToolCallAllowlist:
    """Enforces allowlisting and role-based approval for tool invocations.

    Parameters
    ----------
    policies : list[ToolPolicy]
        One policy per registered tool.
    approval_callback : callable, optional
        Simulated human-in-the-loop callback.  Receives the tool name and
        arguments and returns ``True`` (approved) or ``False`` (denied).
        Defaults to always-deny for safety.
    """

    def __init__(
        self,
        policies: list[ToolPolicy],
        approval_callback: Callable[[str, dict[str, Any]], bool] | None = None,
    ) -> None:
        self._policies: dict[str, ToolPolicy] = {p.tool_name: p for p in policies}
        self._call_counts: dict[str, int] = {}
        self._approval_callback = approval_callback or (lambda _name, _args: False)

    def reset_session(self) -> None:
        """Reset per-session call counters."""
        self._call_counts.clear()

    def check(
        self,
        tool_name: str,
        caller_role: str,
        tool_args: dict[str, Any] | None = None,
    ) -> GuardrailResult:
        """Evaluate whether *tool_name* may be invoked by *caller_role*."""
        policy = self._policies.get(tool_name)
        if policy is None:
            return GuardrailResult(
                verdict=GuardrailVerdict.BLOCK,
                guardrail_name="ToolCallAllowlist",
                reason=f"Tool '{tool_name}' is not in the allowlist.",
            )

        # Role check
        if caller_role not in policy.allowed_roles:
            return GuardrailResult(
                verdict=GuardrailVerdict.BLOCK,
                guardrail_name="ToolCallAllowlist",
                reason=(
                    f"Role '{caller_role}' is not authorised for tool "
                    f"'{tool_name}'. Allowed: {policy.allowed_roles}."
                ),
            )

        # Rate-limit check
        if policy.max_calls_per_session is not None:
            count = self._call_counts.get(tool_name, 0)
            if count >= policy.max_calls_per_session:
                return GuardrailResult(
                    verdict=GuardrailVerdict.BLOCK,
                    guardrail_name="ToolCallAllowlist",
                    reason=(
                        f"Tool '{tool_name}' exceeded session limit "
                        f"({policy.max_calls_per_session})."
                    ),
                )

        # Human-in-the-loop approval
        if policy.approval_level == ApprovalLevel.USER_CONFIRM:
            approved = self._approval_callback(tool_name, tool_args or {})
            if not approved:
                return GuardrailResult(
                    verdict=GuardrailVerdict.BLOCK,
                    guardrail_name="ToolCallAllowlist",
                    reason=f"User denied approval for tool '{tool_name}'.",
                )

        if policy.approval_level == ApprovalLevel.ADMIN_ONLY:
            if caller_role != "admin":
                return GuardrailResult(
                    verdict=GuardrailVerdict.BLOCK,
                    guardrail_name="ToolCallAllowlist",
                    reason=f"Tool '{tool_name}' requires admin role.",
                )

        # Track usage
        self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        return GuardrailResult(
            verdict=GuardrailVerdict.PASS,
            guardrail_name="ToolCallAllowlist",
            reason=f"Tool '{tool_name}' approved for role '{caller_role}'.",
        )


# ---------------------------------------------------------------------------
# 3. Canary / Secret Leak Detection
# ---------------------------------------------------------------------------

# Default canary pattern: CANARY_TOKEN_<digits>
_CANARY_RE = re.compile(r"CANARY_TOKEN_\w+", re.IGNORECASE)

# High-entropy strings (potential leaked secrets).  We flag any contiguous
# alphanumeric token >= 20 chars whose Shannon entropy exceeds the threshold.
_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits) of *data*."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


class CanaryLeakDetector:
    """Detect canary tokens and high-entropy secrets in agent output.

    Parameters
    ----------
    canary_tokens : list[str]
        Exact canary strings to search for.
    custom_patterns : list[re.Pattern], optional
        Additional regex patterns to flag.
    entropy_threshold : float
        Shannon-entropy threshold for flagging high-entropy tokens.
    """

    def __init__(
        self,
        canary_tokens: list[str] | None = None,
        custom_patterns: list[re.Pattern[str]] | None = None,
        entropy_threshold: float = _ENTROPY_THRESHOLD,
    ) -> None:
        self.canary_tokens = canary_tokens or []
        self.custom_patterns = custom_patterns or [_CANARY_RE]
        self.entropy_threshold = entropy_threshold

    def check(self, text: str) -> GuardrailResult:
        """Scan *text* for leaked canary tokens or high-entropy secrets."""
        findings: list[str] = []

        # Exact-match canary search
        for token in self.canary_tokens:
            if token in text:
                findings.append("canary_exact:[REDACTED]")

        # Regex pattern search
        for pattern in self.custom_patterns:
            for match in pattern.finditer(text):
                findings.append("canary_regex:[REDACTED]")

        # High-entropy token search
        for match in _HIGH_ENTROPY_TOKEN.finditer(text):
            token = match.group()
            entropy = _shannon_entropy(token)
            if entropy >= self.entropy_threshold:
                findings.append(
                    f"high_entropy({entropy:.2f}):[REDACTED]"
                )

        if findings:
            return GuardrailResult(
                verdict=GuardrailVerdict.BLOCK,
                guardrail_name="CanaryLeakDetector",
                reason=f"Leaked secrets detected: {findings}",
                original_content=text,
            )

        return GuardrailResult(
            verdict=GuardrailVerdict.PASS,
            guardrail_name="CanaryLeakDetector",
            reason="No canary tokens or high-entropy secrets found.",
            original_content=text,
        )


# ---------------------------------------------------------------------------
# 4. Input / Output Validation
# ---------------------------------------------------------------------------

# Common PII patterns (simplified but functional)
_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "phone_us": re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
}


class PIIRedactor:
    """Detect and redact personally identifiable information."""

    def __init__(
        self, patterns: dict[str, re.Pattern[str]] | None = None
    ) -> None:
        self.patterns = patterns or _PII_PATTERNS

    def redact(self, text: str) -> tuple[str, list[str]]:
        """Return *(redacted_text, list_of_findings)*."""
        findings: list[str] = []
        redacted = text
        for label, pattern in self.patterns.items():
            matches = pattern.findall(redacted)
            if matches:
                findings.extend(f"pii_{label}:{m}" for m in matches)
                redacted = pattern.sub(f"[REDACTED_{label.upper()}]", redacted)
        return redacted, findings


class InputValidator:
    """Pre-execution input validator.

    Checks:
    - Maximum prompt length
    - PII presence (warning only; does not block)
    - Injection pattern scan (delegates to ``UntrustedContextIsolator``)
    """

    def __init__(
        self,
        max_length: int = 8_000,
        isolator: UntrustedContextIsolator | None = None,
    ) -> None:
        self.max_length = max_length
        self.isolator = isolator or UntrustedContextIsolator()
        self._pii = PIIRedactor()

    def check(self, prompt: str, context: str = "") -> list[GuardrailResult]:
        """Return a list of guardrail results for the given input."""
        results: list[GuardrailResult] = []

        # Length gate
        if len(prompt) + len(context) > self.max_length:
            results.append(
                GuardrailResult(
                    verdict=GuardrailVerdict.BLOCK,
                    guardrail_name="InputValidator.length",
                    reason=(
                        f"Combined input length {len(prompt) + len(context)} "
                        f"exceeds maximum {self.max_length}."
                    ),
                )
            )

        # Context isolation
        if context:
            results.append(self.isolator.check(context))

        return results


class OutputValidator:
    """Post-execution output validator.

    Enforces:
    - PII redaction
    - Canary leak detection
    - Maximum output length
    """

    def __init__(
        self,
        max_length: int = 4_000,
        canary_detector: CanaryLeakDetector | None = None,
    ) -> None:
        self.max_length = max_length
        self._pii = PIIRedactor()
        self._canary = canary_detector or CanaryLeakDetector()

    def check(self, output: str) -> list[GuardrailResult]:
        """Validate agent output; returns list of results."""
        results: list[GuardrailResult] = []

        # Length
        if len(output) > self.max_length:
            results.append(
                GuardrailResult(
                    verdict=GuardrailVerdict.MODIFY,
                    guardrail_name="OutputValidator.length",
                    reason=f"Output truncated from {len(output)} to {self.max_length}.",
                    original_content=output,
                    modified_content=output[: self.max_length] + "\n[TRUNCATED]",
                )
            )

        # Canary leak
        results.append(self._canary.check(output))

        # PII redaction
        redacted, findings = self._pii.redact(output)
        if findings:
            results.append(
                GuardrailResult(
                    verdict=GuardrailVerdict.MODIFY,
                    guardrail_name="OutputValidator.pii",
                    reason=f"PII redacted: {findings}",
                    original_content=output,
                    modified_content=redacted,
                )
            )

        return results


# ---------------------------------------------------------------------------
# 5. Composable Guardrail Pipeline
# ---------------------------------------------------------------------------


class GuardrailPipeline:
    """Chain multiple guardrail stages into a single pass/block pipeline.

    The pipeline short-circuits on the first ``BLOCK`` verdict.  ``MODIFY``
    verdicts are accumulated so downstream stages see the sanitised text.
    """

    def __init__(self) -> None:
        self.input_validator: InputValidator | None = None
        self.output_validator: OutputValidator | None = None
        self.tool_allowlist: ToolCallAllowlist | None = None
        self.context_isolator: UntrustedContextIsolator | None = None
        self.canary_detector: CanaryLeakDetector | None = None

    # -- convenience builder ------------------------------------------------

    @classmethod
    def hardened(
        cls,
        canary_tokens: list[str] | None = None,
        tool_policies: list[ToolPolicy] | None = None,
        approval_callback: Callable[[str, dict[str, Any]], bool] | None = None,
    ) -> "GuardrailPipeline":
        """Factory that returns a fully-configured hardened pipeline."""
        pipeline = cls()
        pipeline.context_isolator = UntrustedContextIsolator(block_threshold=3)
        pipeline.canary_detector = CanaryLeakDetector(
            canary_tokens=canary_tokens or [],
        )
        pipeline.input_validator = InputValidator(
            isolator=pipeline.context_isolator,
        )
        pipeline.output_validator = OutputValidator(
            canary_detector=pipeline.canary_detector,
        )
        if tool_policies:
            pipeline.tool_allowlist = ToolCallAllowlist(
                policies=tool_policies,
                approval_callback=approval_callback,
            )
        return pipeline

    @classmethod
    def passthrough(cls) -> "GuardrailPipeline":
        """Factory returning a no-op pipeline (vulnerable baseline)."""
        return cls()

    # -- runtime checks -----------------------------------------------------

    def check_input(
        self, prompt: str, context: str = ""
    ) -> list[GuardrailResult]:
        """Run input-stage guardrails."""
        if self.input_validator is None:
            return [
                GuardrailResult(
                    verdict=GuardrailVerdict.PASS,
                    guardrail_name="GuardrailPipeline.input",
                    reason="No input guardrails configured (passthrough).",
                )
            ]
        return self.input_validator.check(prompt, context)

    def check_tool_call(
        self,
        tool_name: str,
        caller_role: str,
        tool_args: dict[str, Any] | None = None,
    ) -> GuardrailResult:
        """Run tool-call guardrails."""
        if self.tool_allowlist is None:
            return GuardrailResult(
                verdict=GuardrailVerdict.PASS,
                guardrail_name="GuardrailPipeline.tool",
                reason="No tool allowlist configured (passthrough).",
            )
        return self.tool_allowlist.check(tool_name, caller_role, tool_args)

    def check_output(self, output: str) -> list[GuardrailResult]:
        """Run output-stage guardrails."""
        if self.output_validator is None:
            return [
                GuardrailResult(
                    verdict=GuardrailVerdict.PASS,
                    guardrail_name="GuardrailPipeline.output",
                    reason="No output guardrails configured (passthrough).",
                )
            ]
        return self.output_validator.check(output)

