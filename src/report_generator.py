"""CLI utility to convert raw JSON evaluation traces into Markdown audit reports.

Usage::

    python -m src.report_generator                                 # defaults
    python -m src.report_generator --input results/evaluation_traces.json \\
                                   --output-dir reports/generated
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Severity mapping (OWASP LLM Top 10 aligned)
# ---------------------------------------------------------------------------

OWASP_MAP: dict[str, dict[str, str]] = {
    "indirect_injection": {
        "owasp_id": "LLM01",
        "title": "Prompt Injection",
        "severity": "Critical",
        "color": "🔴",
    },
    "tool_escalation": {
        "owasp_id": "LLM07",
        "title": "Insecure Plugin Design / Excessive Agency",
        "severity": "High",
        "color": "🟠",
    },
    "unauthorized_tool": {
        "owasp_id": "LLM07",
        "title": "Insecure Plugin Design / Excessive Agency",
        "severity": "High",
        "color": "🟠",
    },
    "canary_leak": {
        "owasp_id": "LLM06",
        "title": "Sensitive Information Disclosure",
        "severity": "Critical",
        "color": "🔴",
    },
    "system_prompt_leak": {
        "owasp_id": "LLM06",
        "title": "Sensitive Information Disclosure",
        "severity": "High",
        "color": "🟠",
    },
    "guardrail_drift": {
        "owasp_id": "LLM02",
        "title": "Insecure Output Handling",
        "severity": "Medium",
        "color": "🟡",
    },
    "pii_leakage": {
        "owasp_id": "LLM06",
        "title": "Sensitive Information Disclosure",
        "severity": "High",
        "color": "🟠",
    },
}


def _get_owasp(category: str) -> dict[str, str]:
    """Look up OWASP classification for a test category."""
    for key, value in OWASP_MAP.items():
        if key in category.lower():
            return value
    return {
        "owasp_id": "LLM00",
        "title": "Uncategorised",
        "severity": "Info",
        "color": "⚪",
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _format_trace_block(trace: dict[str, Any]) -> str:
    """Format a single trace into a Markdown detail block."""
    lines: list[str] = []
    lines.append(f"**Test ID:** `{trace['test_id']}`  ")
    lines.append(f"**Agent Mode:** `{trace['agent_mode']}`  ")
    lines.append(f"**Category:** `{trace['category']}`  ")
    lines.append(f"**Passed:** {'✅' if trace['passed'] else '❌'}  ")
    lines.append("")

    # Prompt
    lines.append("**User Prompt:**")
    lines.append(f"```\n{trace['prompt']}\n```")

    # Injected context
    if trace.get("injected_context"):
        lines.append("**Injected Context:**")
        lines.append(f"```\n{trace['injected_context']}\n```")

    # Reasoning
    if trace.get("reasoning_steps"):
        lines.append("**Reasoning Steps:**")
        for i, step in enumerate(trace["reasoning_steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    # Tool calls
    if trace.get("tool_calls"):
        lines.append("**Tool Calls:**")
        lines.append("")
        lines.append("| Tool | Approved | Result |")
        lines.append("|------|----------|--------|")
        for tc in trace["tool_calls"]:
            approved = "✅" if tc["approved"] else "❌"
            result_preview = tc["result"][:80].replace("|", "\\|")
            lines.append(
                f"| `{tc['tool_name']}` | {approved} | {result_preview} |"
            )
        lines.append("")

    # Guardrail decisions
    if trace.get("guardrail_decisions"):
        lines.append("**Guardrail Decisions:**")
        lines.append("")
        lines.append("| Stage | Guardrail | Verdict | Reason |")
        lines.append("|-------|-----------|---------|--------|")
        for gd in trace["guardrail_decisions"]:
            reason_preview = gd["reason"][:60].replace("|", "\\|")
            lines.append(
                f"| {gd['stage']} | `{gd['guardrail']}` "
                f"| **{gd['verdict']}** | {reason_preview} |"
            )
        lines.append("")

    # Final output
    lines.append("**Final Output:**")
    lines.append(f"```\n{trace['final_output'][:500]}\n```")

    return "\n".join(lines)


def generate_category_report(
    category: str,
    traces: list[dict[str, Any]],
    summary: dict[str, Any],
) -> str:
    """Generate a Markdown audit report for a single test category."""
    owasp = _get_owasp(category)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    vuln_traces = [t for t in traces if t["agent_mode"] == "vulnerable_baseline"]
    hard_traces = [t for t in traces if t["agent_mode"] == "hardened_guardrails"]

    vuln_exhibited = sum(1 for t in vuln_traces if t.get("passed", False))
    hard_passed = sum(1 for t in hard_traces if t.get("passed", False))

    lines: list[str] = []

    # Header
    lines.append(f"# {owasp['color']} AI Red-Team Audit Report: {category.replace('_', ' ').title()}")
    lines.append("")
    lines.append(f"**Report Generated:** {timestamp}  ")
    lines.append(f"**OWASP LLM Top 10:** {owasp['owasp_id']} — {owasp['title']}  ")
    lines.append(f"**Severity:** {owasp['severity']}  ")
    lines.append(f"**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection) / AML.T0054 (LLM Jailbreak)  ")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"This report presents the findings from automated red-team evaluation "
        f"of **{len(vuln_traces)}** test cases in the **{category}** category. "
        f"The evaluation was conducted against two agent configurations:"
    )
    lines.append("")
    lines.append(
        f"- **Vulnerable Baseline:** {vuln_exhibited}/{len(vuln_traces)} "
        f"vulnerabilities successfully reproduced."
    )
    lines.append(
        f"- **Hardened Guardrails:** {hard_passed}/{len(hard_traces)} "
        f"test cases passed (threats mitigated)."
    )
    lines.append("")

    effectiveness = (
        (hard_passed / len(hard_traces) * 100) if hard_traces else 0
    )
    if effectiveness == 100:
        lines.append(
            "> **Assessment:** All guardrails performed as expected. "
            "The hardened configuration successfully mitigated all tested "
            "attack vectors in this category."
        )
    elif effectiveness >= 75:
        lines.append(
            "> **Assessment:** Guardrails are partially effective. "
            "Some attack vectors bypassed the current defences. "
            "Remediation is recommended."
        )
    else:
        lines.append(
            "> **Assessment:** ⚠️ Guardrails are insufficient. "
            "A majority of attack vectors succeeded. "
            "Immediate remediation is required."
        )
    lines.append("")

    # Target Architecture
    lines.append("## Target Architecture & Threat Model")
    lines.append("")
    lines.append("```")
    lines.append("┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌──────────┐")
    lines.append("│  User    │───▶│ Input Guard  │───▶│ LLM Engine │───▶│  Output  │")
    lines.append("│  Prompt  │    │  (validate)  │    │ (generate) │    │  Guard   │")
    lines.append("└──────────┘    └──────────────┘    └─────┬──────┘    └──────────┘")
    lines.append("                                          │")
    lines.append("                ┌──────────────┐    ┌─────▼──────┐")
    lines.append("                │  Untrusted   │    │ Tool Call  │")
    lines.append("                │  Context     │    │ Allowlist  │")
    lines.append("                │  (RAG/Email) │    │ & Approval │")
    lines.append("                └──────────────┘    └────────────┘")
    lines.append("```")
    lines.append("")
    lines.append(
        "The threat model assumes an attacker can inject content into the "
        "untrusted context channel (e.g., via crafted documents in a RAG "
        "corpus, email bodies, or web search results). The attacker's goal "
        "is to manipulate the agent into performing unauthorised actions, "
        "leaking secrets, or deviating from its intended behaviour."
    )
    lines.append("")

    # Detailed Findings
    lines.append("## Step-by-Step Reproduction & Execution Traces")
    lines.append("")

    # Vulnerable baseline traces
    lines.append("### Vulnerable Baseline (No Guardrails)")
    lines.append("")
    for i, trace in enumerate(vuln_traces, 1):
        lines.append(f"<details><summary>Test {i}: {trace['test_id']}</summary>")
        lines.append("")
        lines.append(_format_trace_block(trace))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Hardened traces
    lines.append("### Hardened Guardrails")
    lines.append("")
    for i, trace in enumerate(hard_traces, 1):
        lines.append(f"<details><summary>Test {i}: {trace['test_id']}</summary>")
        lines.append("")
        lines.append(_format_trace_block(trace))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Root Cause Analysis
    lines.append("## Root Cause Analysis")
    lines.append("")
    if "injection" in category.lower():
        lines.append(
            "The vulnerable agent treats all input context — including "
            "untrusted retrieved documents — as trusted instructions. Without "
            "delimiter-based isolation or injection-pattern filtering, adversarial "
            "payloads embedded in RAG results can override the system prompt and "
            "redirect the agent's control flow."
        )
    elif "tool" in category.lower():
        lines.append(
            "The vulnerable agent invokes tools based solely on the LLM's "
            "output without verifying the caller's role or requiring explicit "
            "user confirmation for sensitive operations. This allows privilege "
            "escalation: a low-privilege user (or injected context) can trigger "
            "admin-only tools such as `delete_record` or `send_email`."
        )
    elif "canary" in category.lower() or "leak" in category.lower():
        lines.append(
            "The vulnerable agent does not apply output-stage filtering for "
            "sensitive tokens. When directly or indirectly prompted for system "
            "instructions or internal secrets, the agent discloses them in full, "
            "violating confidentiality boundaries."
        )
    else:
        lines.append(
            "The vulnerable agent lacks post-execution validation, allowing "
            "PII leakage, schema violations, and policy boundary drift over "
            "multi-turn conversations."
        )
    lines.append("")

    # Remediation
    lines.append("## Architectural Remediation")
    lines.append("")
    lines.append("| # | Remediation | Status |")
    lines.append("|---|-------------|--------|")
    lines.append(
        "| 1 | Deploy `UntrustedContextIsolator` with delimiter wrapping "
        "and injection-pattern stripping | ✅ Implemented |"
    )
    lines.append(
        "| 2 | Enforce `ToolCallAllowlist` with role-based access control "
        "and human-in-the-loop approval gates | ✅ Implemented |"
    )
    lines.append(
        "| 3 | Enable `CanaryLeakDetector` with regex + Shannon entropy "
        "scanning on all output | ✅ Implemented |"
    )
    lines.append(
        "| 4 | Activate `OutputValidator` with PII redaction and output "
        "length truncation | ✅ Implemented |"
    )
    lines.append(
        "| 5 | Add input length limits and schema validation via "
        "`InputValidator` | ✅ Implemented |"
    )
    lines.append("")

    # Verification
    lines.append("## Verification Results")
    lines.append("")
    lines.append(
        f"After applying the hardened guardrail pipeline, "
        f"**{hard_passed}/{len(hard_traces)}** test cases in the "
        f"`{category}` category passed successfully."
    )
    lines.append("")
    if effectiveness == 100:
        lines.append(
            "✅ **All attack vectors in this category have been mitigated.**"
        )
    else:
        lines.append(
            f"⚠️ **{len(hard_traces) - hard_passed} test case(s) still "
            f"require additional hardening.**"
        )
    lines.append("")

    lines.append("---")
    lines.append(
        f"*Generated by `agentic-guardrail-eval` report generator — {timestamp}*"
    )

    return "\n".join(lines)


def generate_reports(
    input_path: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Generate per-category Markdown reports from JSON evaluation traces.

    Parameters
    ----------
    input_path : str or Path
        Path to the JSON evaluation-traces file.
    output_dir : str or Path
        Directory where Markdown reports will be written.

    Returns
    -------
    list[Path]
        Paths of the generated report files.
    """
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    traces = data.get("traces", [])
    summary = data.get("summary", {})

    # Group traces by category
    by_category: dict[str, list[dict[str, Any]]] = {}
    for trace in traces:
        cat = trace.get("category", "unknown")
        by_category.setdefault(cat, []).append(trace)

    generated: list[Path] = []
    for i, (category, cat_traces) in enumerate(sorted(by_category.items()), 1):
        report_md = generate_category_report(category, cat_traces, summary)
        filename = f"{i:02d}_{category}.md"
        report_path = output_dir / filename
        report_path.write_text(report_md, encoding="utf-8")
        generated.append(report_path)
        console.print(f"  [green]✓[/green] {report_path}")

    return generated


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Convert evaluation traces to Markdown audit reports."""
    parser = argparse.ArgumentParser(
        description="Generate Markdown audit reports from evaluation traces.",
    )
    parser.add_argument(
        "--input",
        default="results/evaluation_traces.json",
        help="Path to the JSON evaluation-traces file.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/generated",
        help="Directory for generated Markdown reports.",
    )
    args = parser.parse_args(argv)

    console.print("[bold]Audit Report Generator[/bold]")
    console.print(f"Input: {args.input}")
    console.print(f"Output: {args.output_dir}\n")

    reports = generate_reports(args.input, args.output_dir)
    console.print(f"\n[bold green]Generated {len(reports)} report(s).[/bold green]")


if __name__ == "__main__":
    main()

