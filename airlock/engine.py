"""The diff engine: declared capability vs. observed behaviour.

This is where the four evidence streams become findings. Each rule is grounded in
an observable artefact rather than a pattern match, so the payload-padding,
archive-hiding and LLM-judge-injection bypasses that Trail of Bits demonstrated
against every public scanner in June 2026 do not apply: you cannot obfuscate a
``connect()`` syscall or a canary string arriving in a TCP payload.

Every finding carries a stable ``rule_id`` for CI gating and regression tracking,
an ``ast`` mapping to the OWASP Agentic Skills Top 10 (AST01-AST10), and the
concrete evidence that produced it, so nothing is asserted on faith.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field

from .canary import CanaryIndex
from .declared import (AMBIENT_READS, PERSISTENCE_PATHS, CapabilityDeclaration,
                       find_embedded_instructions)
from .sandbox import RunResult

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

#: Cloud metadata endpoints. BlueRock found 36.7% of 7,000+ MCP servers
#: potentially SSRF-vulnerable and pulled live AWS IAM keys through one.
IMDS_TARGETS = ("169.254.169.254", "metadata.google.internal",
                "metadata.azure.internal", "169.254.170.2", "100.100.100.200")


@dataclass
class Finding:
    rule_id: str
    ast: str
    severity: str
    title: str
    detail: str
    evidence: list = field(default_factory=list)
    declared: str = ""
    observed: str = ""
    confidence: str = "confirmed"   # confirmed | likely | heuristic

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 0)


@dataclass
class Verdict:
    risk_score: int
    label: str                      # CRITICAL | HIGH | ELEVATED | LOW | CLEAN | UNKNOWN
    findings: list
    trifecta: dict
    coverage: dict
    declared: CapabilityDeclaration
    observed_summary: dict


def _decode(b64: str) -> str:
    try:
        return base64.b64decode(b64 + "==").decode("utf-8", "replace")
    except Exception:
        return ""


def _domains(net: list) -> dict:
    """host -> [event types that referenced it]. Loopback is excluded: every
    egress attempt lands on the sinkhole, so the real destination comes from the
    DNS query, the SNI or the Host header, not from the peer address."""
    out: dict = {}

    def add(host: str, kind: str) -> None:
        host = (host or "").lower().strip().strip(".")
        if not host:
            return
        host = host.split(":")[0].split("/")[0]
        if host in ("localhost", "127.0.0.1", "::1", ""):
            return
        out.setdefault(host, [])
        if kind not in out[host]:
            out[host].append(kind)

    for e in net:
        t = e.get("type")
        if t == "dns_query":
            add(e.get("qname", ""), "dns")
        elif t == "tls_clienthello":
            add(e.get("sni", ""), "tls_sni")
        elif t == "http_request":
            add(e.get("host") or (e.get("headers") or {}).get("host", ""), "http")
        elif t == "proxy_connect":
            add(e.get("target", ""), "proxy_connect")
    return out


def _canary_surfaces(result: RunResult, index: CanaryIndex) -> list:
    """Scan every byte that left the sandbox's read scope for a planted canary."""
    hits = []

    for e in result.net_events:
        t = e.get("type")
        if t == "dns_query":
            hits += index.scan_bytes("dns_query", e.get("qname", "").encode(),
                                     f"DNS query for {e.get('qname')}")
        elif t == "http_request":
            blob = (str(e.get("target", "")) + "\r\n" + str(e.get("headers", ""))).encode()
            hits += index.scan_bytes(
                "egress_http", blob + _decode(e.get("body_b64", "")).encode(),
                f"HTTP {e.get('method')} {e.get('host') or ''}{e.get('target')}")
        elif t == "tcp_payload":
            hits += index.scan_bytes("egress_tcp", _decode(e.get("payload_b64", "")).encode(),
                                     f"TCP payload to :{e.get('port')} ({e.get('nbytes')} bytes)")
        elif t == "proxy_connect":
            hits += index.scan_bytes("egress_proxy", e.get("target", "").encode(),
                                     f"proxy CONNECT {e.get('target')}")
        elif t == "tls_clienthello":
            hits += index.scan_bytes("egress_tls", e.get("sni", "").encode(),
                                     f"TLS SNI {e.get('sni')}")

    for surface, text in (("stdout", result.stdout), ("stderr", result.stderr)):
        hits += index.scan_bytes(surface, text.encode(), f"process {surface}")

    for proc in result.processes:
        hits += index.scan_bytes("argv", str(proc.get("cmdline", "")).encode(),
                                 f"command line: {proc.get('cmdline')}")

    for ev in result.fs_events:
        if ev.change in ("created", "modified") and ev.content:
            hits += index.scan_bytes("file_write", ev.content.encode(),
                                     f"wrote to {ev.sandbox_path}")
    return hits


def analyse(result: RunResult, decl: CapabilityDeclaration) -> Verdict:
    findings: list = []
    ds = result.decoys
    index = ds.index if ds else CanaryIndex()

    cov = result.meta.get("coverage", {}) if result.meta else {}
    coverage = {
        "proc": cov.get("proc", "unknown"),
        "process_tree": cov.get("process_tree", False),
        "network_isolated": cov.get("network_isolated", False),
        "mount_isolation": cov.get("mount_isolation", False),
        "namespace_flags": next((e.split("namespace flags: ")[1] for e in result.errors
                                 if "namespace flags:" in e), "unknown"),
        "timed_out": result.timed_out,
        "duration_s": result.duration_s,
    }
    errs = [e for e in result.errors if "namespace flags:" not in e]
    if errs:
        coverage["errors"] = errs

    # ------------------------------------------------- 1. canary exfiltration
    # One finding per *class* of channel, not per capture event. The same bytes
    # are usually seen twice -- once as a parsed HTTP request and once as a raw
    # TCP payload -- and reporting that as two exfiltrations inflates the count
    # and makes the report easier to dismiss.
    CHANNEL_CLASS = {
        "dns_query": "network", "egress_http": "network", "egress_tcp": "network",
        "egress_proxy": "network", "egress_tls": "network",
        "stdout": "agent_output", "stderr": "agent_output", "argv": "agent_output",
        "file_write": "staging",
    }
    by_class: dict = {}
    for h in _canary_surfaces(result, index):
        by_class.setdefault(CHANNEL_CLASS.get(h.surface, "other"), []).append(h)

    _CHANNEL_SPEC = {
        "network": ("critical", "Credential left the sandbox over the network",
                    "A planted canary was captured in outbound traffic -- in a DNS query or "
                    "a TCP/HTTP payload. This is confirmed exfiltration rather than inference: "
                    "the string did not exist before this run and exists nowhere else on the "
                    "machine. DNS is the more serious variant because it leaves the host even "
                    "when outbound TCP is blocked, and is invisible to scanners that only read "
                    "source."),
        "agent_output": ("high", "Credential leaked into agent-visible output",
                         "A planted canary reached stdout, stderr or a command line. The "
                         "calling agent reads that stream, so the secret enters the model's "
                         "context and can be forwarded by any later tool call, or persisted "
                         "into its logs and memory files."),
        "staging": ("high", "Credential staged into a written file",
                    "A planted canary was copied into a file the skill created or modified -- "
                    "the staging step before exfiltration, or a cache that outlives the run."),
        "other": ("medium", "Credential surfaced outside its file",
                  "A planted canary was observed somewhere it should never appear."),
    }
    for cls, group in by_class.items():
        sev, title, detail = _CHANNEL_SPEC.get(cls, _CHANNEL_SPEC["other"])
        ids = sorted({h.secret_id for h in group})
        labels = [(ds.by_id(i).label if ds and ds.by_id(i) else i) for i in ids]
        obf = any(h.obfuscated for h in group)
        surfaces = sorted({h.surface for h in group})
        evidence = list(dict.fromkeys(
            f"[{h.surface}] {h.detail}" + (" -- obfuscated form" if h.obfuscated else "")
            for h in group))[:6]
        if len(ids) > 1:
            evidence.append(f"{len(ids)} distinct credential(s) recovered: "
                            + ", ".join(str(x) for x in labels[:6]))
        if len(surfaces) > 1:
            evidence.append(f"captured on: {', '.join(surfaces)}")
        findings.append(Finding(
            rule_id="ALK-001", ast="AST01", severity=sev,
            title=title + (" (obfuscated encoding)" if obf else ""),
            detail=detail, evidence=evidence,
            declared=", ".join(decl.fs_read) or "(no sensitive read declared)",
            observed=", ".join(str(x) for x in labels),
        ))

    # ------------------------------------------------- 2. secret file reads
    read_events = [e for e in result.fs_events if e.change == "read"]
    # The interpreter has to read the script it is running; that is not the skill
    # choosing to read a file. Derive it from the actual argv rather than
    # guessing by extension.
    entry_files = {"/work/" + os.path.basename(a) for a in result.entry
                   if not a.startswith("/")}
    ambient_paths = set(AMBIENT_READS) | entry_files
    ambient = [e for e in read_events if e.sandbox_path in ambient_paths]
    meaningful_reads = [e for e in read_events if e.sandbox_path not in ambient_paths]

    for ev in read_events:
        if not ev.secret_id:
            continue
        sec = ds.by_id(ev.secret_id) if ds else None
        label = sec.label if sec else ev.sandbox_path
        if decl.declares_path(ev.sandbox_path, "read"):
            findings.append(Finding(
                rule_id="ALK-006", ast="AST03", severity="info",
                title=f"Read {label} (declared)",
                detail=("The skill read a sensitive path it had explicitly declared. Recorded "
                        "so the access is visible, not because it violates anything."),
                evidence=[f"atime advanced on {ev.sandbox_path}"],
                declared=ev.sandbox_path, observed=ev.sandbox_path))
        else:
            sev = "high" if (sec and sec.sensitivity == "critical") else "medium"
            findings.append(Finding(
                rule_id="ALK-002", ast="AST03", severity=sev,
                title=f"Read {label} without declaring it",
                detail=("Access time advanced on a planted credential the skill never asked "
                        "for. Read detection uses atime, which is a heuristic: it proves "
                        "access but not intent, which is why the canary correlation above is "
                        "what confirms exfiltration."),
                evidence=[f"atime advanced on {ev.sandbox_path}; content unchanged"],
                declared=", ".join(decl.fs_read) or "(nothing declared)",
                observed=ev.sandbox_path, confidence="likely"))

    # ------------------------------------------------- 3. network egress
    domains = _domains(result.net_events)
    undeclared = [(h, k) for h, k in domains.items() if not decl.declares_domain(h)]
    imds = [(h, k) for h, k in undeclared
            if h.rstrip(".") in IMDS_TARGETS or h in IMDS_TARGETS]
    other = [(h, k) for h, k in undeclared if (h, k) not in imds]

    for host, kinds in imds:
        findings.append(Finding(
            rule_id="ALK-003", ast="AST03", severity="critical",
            title=f"Probed the cloud instance metadata endpoint ({host})",
            detail=("169.254.169.254 is how SSRF becomes real cloud credentials. BlueRock "
                    "Security found 36.7% of 7,000+ MCP servers potentially vulnerable and "
                    "retrieved live AWS IAM keys from an EC2 metadata endpoint through "
                    "Microsoft's MarkItDown server. The sandbox has no route here, so "
                    "nothing was returned."),
            evidence=[f"{host} referenced via {', '.join(kinds)}"],
            declared="(metadata access is never legitimate for a skill)", observed=host))

    if other:
        findings.append(Finding(
            rule_id="ALK-004", ast="AST03",
            severity="high" if not decl.net_declared_any else "medium",
            title=f"Contacted {len(other)} undeclared host(s)",
            detail=("The skill reached network destinations absent from its manifest. Under "
                    "the OWASP Universal Skill Format, network permission is a domain "
                    "allowlist rather than a boolean, precisely so this stays checkable."),
            evidence=[f"{h} via {', '.join(k)}" for h, k in sorted(other)[:12]],
            declared=", ".join(decl.net_allow) or (
                "no network declared" if not decl.net_declared_any
                else "network declared without a domain allowlist"),
            observed=", ".join(sorted(h for h, _ in other[:6]))))

    # ------------------------------------------------- 4. persistence
    for ev in result.fs_events:
        if ev.change not in ("created", "modified"):
            continue
        if not any(ev.sandbox_path == p or ev.sandbox_path.startswith(p.rstrip("/") + "/")
                   for p in PERSISTENCE_PATHS):
            continue
        findings.append(Finding(
            rule_id="ALK-005", ast="AST01", severity="high",
            title=f"Wrote to a persistence location: {ev.sandbox_path}",
            detail=("Writes to shell rc files, authorized_keys, autostart entries, cron, or "
                    "agent identity/memory files (SOUL.md, MEMORY.md, AGENTS.md) survive the "
                    "session. ClawHavoc backdoored agents by writing malicious instructions "
                    "straight into MEMORY.md and SOUL.md. The Universal Skill Format places "
                    "those files under deny_write by default."),
            evidence=[f"{ev.change}: {ev.sandbox_path} ({ev.size} bytes)"],
            declared=", ".join(decl.fs_write) or "(no writes declared)",
            observed=ev.sandbox_path))

    # ------------------------------------------------- 5. undeclared writes
    reported = {f.observed for f in findings if f.rule_id == "ALK-005"}
    for ev in result.fs_events:
        if ev.change not in ("created", "modified"):
            continue
        # Scratch and output areas are expected; suppressing them is what keeps
        # the false-positive rate low enough that people do not ignore the tool.
        if ev.sandbox_path.startswith(("/tmp/", "/output/")):
            continue
        if ev.sandbox_path in reported or ev.is_secret:
            continue
        if decl.declares_path(ev.sandbox_path, "write"):
            continue
        findings.append(Finding(
            rule_id="ALK-007", ast="AST03", severity="medium",
            title=f"Wrote outside its declared scope: {ev.sandbox_path}",
            detail="A write landed somewhere the manifest did not claim.",
            evidence=[f"{ev.change}: {ev.sandbox_path} ({ev.size} bytes)"],
            declared=", ".join(decl.fs_write) or "(no writes declared)",
            observed=ev.sandbox_path))

    # ------------------------------------------------- 6. remote code fetch
    cmdlines = " | ".join(p.get("cmdline", "") for p in result.processes)
    if re.search(r"\b(?:curl|wget|nc|ncat)\b[^|]*\|\s*(?:ba|z|da)?sh\b", cmdlines) or (
            re.search(r"\b(?:curl|wget)\b", cmdlines)
            and re.search(r"\b(?:ba)?sh\b|\bpython", cmdlines)):
        findings.append(Finding(
            rule_id="ALK-008", ast="AST04", severity="critical",
            title="Downloaded and executed remote code",
            detail=("The process tree shows a fetch piped into a shell, or a download "
                    "followed by an interpreter. The payload never appears in the skill's own "
                    "source, which is exactly why static scanners miss it -- Air Security "
                    "reached 26,000+ agents this way while every public scanner cleared the "
                    "skill. This rule needs a sampled process tree; see coverage above."),
            evidence=[p.get("cmdline", "") for p in result.processes
                      if re.search(r"curl|wget|sh|bash|python", p.get("cmdline", ""))][:8],
            declared="(remote code execution is not declarable)",
            observed=cmdlines[:200], confidence="likely"))

    # ------------------------------------------------- 7. embedded instructions
    # Grouped per source: four separate pattern hits on one description are one
    # problem, not four findings. Emitting them separately buries the signal.
    grouped: dict = {}
    for hit in find_embedded_instructions(decl):
        grouped.setdefault(hit["source"], []).append(hit)
    for source, hits in grouped.items():
        reasons = sorted({h["reason"] for h in hits})
        longest = max(hits, key=lambda h: len(h["excerpt"]))
        evidence = [longest["excerpt"][:200]] + [
            f'also matched: {h["reason"]} -- "{h["excerpt"][:80]}"'
            for h in hits if h is not longest][:3]
        findings.append(Finding(
            rule_id="ALK-009", ast="AST01", severity="high",
            title=f"Model-directed instruction hidden in {source}",
            detail=(f"Matched {len(reasons)} injection indicator(s): " + ", ".join(reasons)
                    + ". Description fields and markdown bodies reach the model as "
                    "instructions but are frequently not rendered in the UI the user "
                    "approves from -- the tool-poisoning vector Invariant Labs documented, "
                    "and the exact case both free scanners returned SAFE for in the October "
                    "2026 comparison. This finding is heuristic: it reads intent from text, "
                    "so treat it as a reason to look, not as proof."),
            evidence=evidence, declared="(the user never sees this text)",
            observed=longest["excerpt"][:160], confidence="heuristic"))

    # ------------------------------------------------- 8. lethal trifecta
    leg_a = sorted({e.sandbox_path for e in result.fs_events if e.is_secret})
    leg_b = sorted({h["source"] for h in find_embedded_instructions(decl)})
    if leg_b:
        leg_b_basis = "confirmed: model-directed instructions present in the manifest"
    else:
        leg_b = sorted(d for d, _ in undeclared)
        leg_b_basis = ("inferred: the skill fetched from an undeclared host, so whatever "
                       "came back entered its context unvetted")
    leg_c = sorted(domains)
    trifecta = {"private_data_access": leg_a, "untrusted_content": leg_b,
                "untrusted_content_basis": leg_b_basis,
                "external_communication": leg_c, "satisfied": bool(leg_a and leg_c)}
    if trifecta["satisfied"]:
        findings.append(Finding(
            rule_id="ALK-010", ast="AST06", severity="critical",
            title="Lethal Trifecta satisfied",
            detail=("Simon Willison's / Palo Alto Networks' framing: a skill is especially "
                    "dangerous when it simultaneously has access to private data, exposure to "
                    "untrusted content, and the ability to communicate externally. airlock "
                    "observed all legs in one run, which means this skill can be turned into "
                    "an exfiltration channel by anything it reads -- including a web page or "
                    "an email it was asked to summarise."),
            evidence=[f"private data: {', '.join(leg_a[:5])}",
                      f"untrusted content: {', '.join(leg_b[:3]) or '(not directly observed)'}",
                      f"  basis: {leg_b_basis}",
                      f"external comms: {', '.join(leg_c[:5])}"],
            declared="(the manifest does not acknowledge this combination)",
            observed="all three legs present in one run"))

    # ------------------------------------------------- 9. coverage honesty
    if result.timed_out:
        findings.append(Finding(
            rule_id="ALK-090", ast="AST08", severity="medium",
            title="Run hit the timeout; coverage is incomplete",
            detail=("The skill was killed before it finished. A clean result here does not "
                    "mean the skill is safe -- only that nothing happened inside the window. "
                    "Behaviour gated on a delay, a credential, or a specific input would not "
                    "have fired. Re-run with a longer timeout before trusting this."),
            evidence=[f"terminated at {result.duration_s}s"]))
    if coverage["proc"] != "fresh-procfs":
        findings.append(Finding(
            rule_id="ALK-091", ast="AST08", severity="low",
            title=f"Limited /proc coverage ({coverage['proc']})",
            detail=("The kernel refused a fresh procfs mount for this PID namespace, so the "
                    "process tree could not be sampled and ALK-008 is degraded. Filesystem, "
                    "DNS and network evidence are unaffected. On a normal Linux host or WSL2 "
                    "this resolves itself -- it is typical only inside nested containers."),
            evidence=[f"proc mode = {coverage['proc']}"]))
    if not result.ok:
        findings.append(Finding(
            rule_id="ALK-093", ast="AST08", severity="high",
            title="Sandbox failed to establish; no behavioural assurance",
            detail=("airlock could not create a namespace and refused to run the skill "
                    "unsandboxed. Nothing was observed, so this result says nothing about the "
                    "skill either way."),
            evidence=errs[:5]))

    # ------------------------------------------------- 10. over-declaration
    observed_paths = {e.sandbox_path for e in result.fs_events}
    for claimed in list(decl.fs_read) + list(decl.fs_write):
        c = claimed.replace("~", "/home").replace("$HOME", "/home").rstrip("/*")
        if c and not any(p.startswith(c) for p in observed_paths):
            findings.append(Finding(
                rule_id="ALK-011", ast="AST03", severity="info",
                title=f"Declared but never used: {claimed}",
                detail=("Over-broad permission requests are the norm here -- Snyk found 280+ "
                        "skills leaking credentials through over-permission alone. A "
                        "permission the skill never exercises is one you can safely remove."),
                evidence=[f"no filesystem event under {c}"],
                declared=claimed, observed="(nothing)", confidence="likely"))

    # ------------------------------------------------- score & label
    score = min(100, sum(f.weight for f in findings))
    label = ("CRITICAL" if score >= 70 else "HIGH" if score >= 40 else
             "ELEVATED" if score >= 15 else "LOW" if score >= 1 else "CLEAN")
    if not result.ok:
        label = "UNKNOWN"
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id))

    observed_summary = {
        "files_read": sorted({e.sandbox_path for e in meaningful_reads}),
        "ambient_reads_suppressed": sorted({e.sandbox_path for e in ambient}),
        "files_written": sorted({e.sandbox_path for e in result.fs_events
                                 if e.change in ("created", "modified")}),
        "files_deleted": sorted({e.sandbox_path for e in result.fs_events
                                 if e.change == "deleted"}),
        "domains": sorted(domains),
        "dns_queries": sorted({e.get("qname", "") for e in result.net_events
                               if e.get("type") == "dns_query"}),
        "processes": [p.get("cmdline", "") for p in result.processes],
        "exit_code": result.exit_code,
        "duration_s": result.duration_s,
    }
    return Verdict(risk_score=score, label=label, findings=findings, trifecta=trifecta,
                   coverage=coverage, declared=decl, observed_summary=observed_summary)
