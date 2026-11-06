"""SARIF 2.1.0 emitter.

This is the integration surface that matters most. SARIF drops straight into
GitHub's Security -> Code Scanning tab via ``github/codeql-action/upload-sarif``,
so airlock can gate a merge on a PR without anyone building a custom pipeline --
and it is the same shape OWASP already documents for the static scanners listed
on its AST10 skill-scanner-integration page.
"""

from __future__ import annotations

from .engine import Verdict

TOOL_NAME = "airlock"
TOOL_INFO_URI = "https://github.com/MuhammadBilal0021/airlock"

_SEVERITY_MAP = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "6.0",
                      "low": "3.0", "info": "1.0"}
_RULE_HELP = {
    "ALK-001": "A canary planted inside a decoy credential was captured leaving the sandbox.",
    "ALK-002": "A decoy credential was read without being declared in the manifest.",
    "ALK-003": "The cloud instance metadata endpoint was probed (SSRF to real credentials).",
    "ALK-004": "Network egress reached hosts absent from the declared allowlist.",
    "ALK-005": "A write landed in a location that persists across sessions.",
    "ALK-006": "A declared sensitive read occurred. Informational.",
    "ALK-007": "A write landed outside the declared scope.",
    "ALK-008": "Remote code was fetched and executed; the payload is not in the skill source.",
    "ALK-009": "Model-directed instructions were hidden in text a UI may never render.",
    "ALK-010": "Private data + untrusted content + external egress all observed in one run.",
    "ALK-011": "A declared permission was never exercised and can be removed.",
    "ALK-012": "A decoy credential gained group or other-user read/write permission bits.",
    "ALK-013": "Shell history or audit evidence was deleted during the run (anti-forensics).",
    "ALK-090": "The run timed out, so the result does not prove absence of malice.",
    "ALK-091": "A fresh procfs could not be mounted, so the process tree was not sampled.",
    "ALK-093": "The sandbox could not be established; no behavioural assurance was obtained.",
}


def to_sarif(verdict: Verdict, *, target: str, version: str = "0.1.0") -> dict:
    rules, results = {}, []
    for f in verdict.findings:
        if f.rule_id not in rules:
            help_text = _RULE_HELP.get(f.rule_id, "")
            rules[f.rule_id] = {
                "id": f.rule_id, "name": f.rule_id,
                "shortDescription": {"text": f.title.split(":")[0][:120]},
                "fullDescription": {"text": f.detail},
                "helpUri": TOOL_INFO_URI,
                "help": {"text": help_text, "markdown": help_text},
                "defaultConfiguration": {"level": _SEVERITY_MAP.get(f.severity, "warning")},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
                    "tags": ["security", "ai-agents", "supply-chain", f.ast, "airlock"],
                    "precision": f.confidence,
                },
            }
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": sorted(rules).index(f.rule_id),
            "level": _SEVERITY_MAP.get(f.severity, "warning"),
            "message": {"text": f.title + ("\n\n" + f.detail if f.detail else "")
                        + ("\n\nDeclared: " + f.declared if f.declared else "")
                        + ("\nObserved: " + f.observed if f.observed else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": target, "uriBaseId": "%SRCROOT%"}}}],
            "properties": {"evidence": f.evidence[:10], "ast": f.ast, "severity": f.severity},
        })

    d = verdict.declared
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME, "version": version, "semanticVersion": version,
                "informationUri": TOOL_INFO_URI,
                "rules": [rules[k] for k in sorted(rules)]}},
            "results": results,
            "invocations": [{
                "executionSuccessful": verdict.label != "UNKNOWN",
                "properties": {"riskScore": verdict.risk_score, "verdict": verdict.label,
                               "lethalTrifecta": verdict.trifecta.get("satisfied", False),
                               "coverage": verdict.coverage}}],
            "properties": {
                "airlock/observed": verdict.observed_summary,
                "airlock/declared": {"fs_read": d.fs_read, "fs_write": d.fs_write,
                                     "net_allow": d.net_allow, "shell": d.shell,
                                     "tools": d.tools, "manifests": d.manifests_found},
            },
        }],
    }
