"""airlock -- behavioural sandbox for agent skills and MCP servers.

Zero runtime dependencies. Requires Linux with ``unshare`` (util-linux);
WSL2 is the supported path on Windows.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .declared import CapabilityDeclaration, find_embedded_instructions, scan_tree
from .engine import SEVERITY_ORDER, Finding, Verdict, analyse
from .render import render_markdown, render_terminal
from .sandbox import cleanup, run_skill
from .sarif import to_sarif

ENTRY_CANDIDATES = ("run.sh", "entrypoint.sh", "main.sh", "start.sh", "install.sh",
                    "setup.sh", "main.py", "server.py", "run.py", "index.js")
#: Real registry skills keep code beside SKILL.md rather than at the package
#: root. Without a second look these can only ever be declaration-checked, which
#: makes behavioural analysis unavailable for precisely the packages the tool
#: exists to inspect.
SUBDIR_ENTRY_DIRS = ("scripts", "bin", "tools", "hooks")
ENTRY_STEMS = ("main", "run", "cli", "entry", "entrypoint", "start", "install",
               "setup", "server")
_SEV_BY_NAME = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 99}


def detect_entry(work: Path):
    """Decide what to execute, and say why.

    A skill with no executable artefact cannot be analysed dynamically. Rather
    than silently degrading, airlock reports that honestly and falls back to
    declaration-only checks -- coverage honesty is a feature, not a nicety.
    """
    for name in ENTRY_CANDIDATES:
        p = work / name
        if p.exists():
            if name.endswith(".py"):
                # The sandbox mounts /usr, not the caller's venv or CI toolcache.
                return ["/usr/bin/python3", name], f"auto-detected {name}"
            if name.endswith(".js"):
                return ["node", name], f"auto-detected {name}"
            return ["/bin/sh", name], f"auto-detected {name}"
    for cand in sorted(work.glob("*.sh")):
        return ["/bin/sh", cand.name], f"auto-detected {cand.name}"
    for cand in sorted(work.glob("*.py")):
        return ["/usr/bin/python3", cand.name], f"auto-detected {cand.name}"
    nested = _nested_entry(work)
    if nested is not None:
        relative = nested.relative_to(work).as_posix()
        interpreter = "/usr/bin/python3" if nested.suffix == ".py" else "/bin/sh"
        return [interpreter, relative], f"auto-detected {relative}"
    return [], "no executable artefact found -- declaration checks only"


def _nested_entry(work: Path):
    """Find a plausible entrypoint under a ``scripts/`` style directory.

    Deliberately conservative: only a conventional subdirectory, and only either
    a recognised entry stem (``main.py``, ``run.sh``, ...) or a single
    unambiguous script. Anything else stays declaration-only rather than running
    an arbitrary helper the author never meant as an entrypoint.
    """
    for name in SUBDIR_ENTRY_DIRS:
        directory = work / name
        if not directory.is_dir() or directory.is_symlink():
            continue
        candidates = sorted(
            path for path in directory.iterdir()
            if path.is_file() and not path.is_symlink()
            and path.suffix in (".py", ".sh")
            and not path.name.startswith(("_", ".")))
        if not candidates:
            continue
        preferred = [path for path in candidates if path.stem in ENTRY_STEMS]
        target = (preferred[0] if preferred
                  else candidates[0] if len(candidates) == 1 else None)
        if target is not None:
            return target
    return None


def _static_only_verdict(decl, target: str, reason: str) -> Verdict:
    """Verdict for a target that could not be executed."""
    findings = []
    grouped = {}
    for hit in find_embedded_instructions(decl):
        grouped.setdefault(hit["source"], []).append(hit)
    for source, hits in grouped.items():
        reasons = sorted({h["reason"] for h in hits})
        longest = max(hits, key=lambda h: len(h["excerpt"]))
        findings.append(Finding(
            rule_id="ALK-009", ast="AST01", severity="high",
            title=f"Model-directed instruction hidden in {source}",
            detail=(f"Matched {len(reasons)} injection indicator(s): " + ", ".join(reasons) +
                    ". Description fields and markdown bodies reach the model as instructions "
                    "but are frequently not rendered in the UI the user approves from. "
                    "Heuristic: this reads intent from text."),
            evidence=[longest["excerpt"][:200]], declared="(the user never sees this text)",
            observed=longest["excerpt"][:160], confidence="heuristic"))
    findings.append(Finding(
        rule_id="ALK-092", ast="AST08", severity="medium",
        title="Dynamic analysis not possible for this target",
        detail=(f"{reason}. airlock found no executable artefact, so there is no behaviour to "
                "observe and only the declaration was checked. This is the weakest form of "
                "assurance and is the entire reason pattern-only scanners get bypassed -- do "
                "not read this result as a clean bill of health."),
        evidence=[f"target: {target}"]))
    score = min(100, sum(f.weight for f in findings))
    label = ("CRITICAL" if score >= 70 else "HIGH" if score >= 40 else
             "ELEVATED" if score >= 15 else "LOW" if score >= 1 else "CLEAN")
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id))
    return Verdict(
        risk_score=score, label=label, findings=findings,
        trifecta={"private_data_access": [], "untrusted_content": [],
                  "external_communication": [], "satisfied": False},
        coverage={"proc": "n/a", "process_tree": False, "network_isolated": False,
                  "mount_isolation": False, "namespace_flags": "none (not executed)",
                  "timed_out": False, "duration_s": 0.0, "static_only": True},
        declared=decl,
        observed_summary={"files_read": [], "files_written": [], "files_deleted": [],
                          "domains": [], "dns_queries": [], "processes": [],
                          "exit_code": None, "duration_s": 0.0})


def _verdict_json(v: Verdict, target: str) -> dict:
    d = v.declared
    return {
        "tool": "airlock", "version": __version__, "target": target,
        "verdict": v.label, "risk_score": v.risk_score, "coverage": v.coverage,
        "lethal_trifecta": v.trifecta,
        "declared": {"name": d.name, "version": d.version, "manifests": d.manifests_found,
                     "fs_read": d.fs_read, "fs_write": d.fs_write,
                     "fs_write_declared": d.fs_write_declared, "fs_deny_write": d.fs_deny_write,
                     "net_allow": d.net_allow,
                     "shell": d.shell, "tools": d.tools, "risk_tier": d.risk_tier},
        "observed": v.observed_summary,
        "findings": [{"rule_id": f.rule_id, "ast": f.ast, "severity": f.severity,
                      "title": f.title, "detail": f.detail, "evidence": f.evidence,
                      "declared": f.declared, "observed": f.observed,
                      "confidence": f.confidence} for f in v.findings],
    }


def run_target(target: Path, entry_spec, timeout: float, extra_env=None, require_bounded=False):
    """Declare-then-observe one target: the single path behind every verdict.

    ``scan`` and the MCP server both go through here so an agent-callable scan
    cannot drift from the command-line one. Returns ``(verdict, run_dir)``, where
    ``run_dir`` is None when the target could not be executed.
    """
    base = target if target.is_dir() else target.parent
    decl = scan_tree(base)
    entry = entry_spec.split() if entry_spec else None
    if entry is None:
        entry, reason = detect_entry(base)
    if not entry:
        return _static_only_verdict(decl, str(target), reason), None
    if require_bounded:
        import os
        from .bounded import verify_limits, DEFAULTS
        from .storage import verify_storage
        verify_limits(DEFAULTS)
        storage_root = os.environ.get('AIRLOCK_STORAGE_ROOT')
        if not storage_root or Path(tempfile.gettempdir()).resolve() != Path(storage_root).resolve():
            raise RuntimeError('MCP execution requires the bounded storage launcher')
        verify_storage(storage_root)
    result = run_skill(target, entry=entry, timeout=timeout, extra_env=extra_env)
    return analyse(result, decl), result.run_dir


def cmd_scan(args) -> int:
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"airlock: no such path: {target}", file=sys.stderr)
        return 2

    verdict, run_dir = run_target(target, args.entry, args.timeout,
                                  json.loads(args.env) if args.env else None)

    if args.format == "json":
        text = json.dumps(_verdict_json(verdict, str(target)), indent=2)
    elif args.format == "sarif":
        text = json.dumps(to_sarif(verdict, target=str(target), version=__version__), indent=2)
    elif args.format == "markdown":
        text = render_markdown(verdict, str(target), version=__version__)
    else:
        text = render_terminal(verdict, str(target))

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"airlock: wrote {args.format} report to {out}")
    else:
        print(text)

    if run_dir is not None:
        if args.keep:
            print(f"airlock: run directory preserved at {run_dir}", file=sys.stderr)
        else:
            cleanup(run_dir)

    if verdict.label == "UNKNOWN":
        return 2
    worst = max((SEVERITY_ORDER.get(f.severity, 0) for f in verdict.findings), default=0)
    return 1 if worst >= _SEV_BY_NAME.get(args.fail_on, 99) else 0


def cmd_policy(args) -> int:
    """Emit a least-privilege manifest derived from what the skill actually did.

    Turns observation into remediation: instead of only saying "this is bad",
    hand back the exact permissions block the skill needs and nothing more.
    Maps directly onto the AST03 mitigation (least-privilege manifests).
    """
    target = Path(args.target).expanduser()
    base = target if target.is_dir() else target.parent
    decl = scan_tree(base)
    entry, reason = detect_entry(base)
    if not entry:
        print(f"airlock: cannot derive a policy -- {reason}", file=sys.stderr)
        return 2
    result = run_skill(target, entry=entry, timeout=args.timeout)
    if not result.ok:
        print("airlock: sandbox failed; cannot derive a policy", file=sys.stderr)
        if not args.keep:
            cleanup(result.run_dir)
        return 2
    v = analyse(result, decl)
    o = v.observed_summary
    reads = sorted({p for p in o["files_read"] if p.startswith("/home") or p.startswith("/work")})
    writes = sorted({p for p in o["files_written"]
                     if not p.startswith(("/tmp/", "/output/"))})
    domains = sorted(o["domains"])
    tier = ("L3" if v.label == "CRITICAL" else "L2" if v.label == "HIGH"
            else "L1" if v.label == "ELEVATED" else "L0")

    def block(items, indent="      "):
        return "".join(f"{indent}- {i}\n" for i in items) or f"{indent}[]\n"

    text = (
        "---\n"
        "# Least-privilege manifest derived by airlock from one observed run.\n"
        "# Review before trusting it: a single run exercises a single code path.\n"
        f"name: {decl.name or Path(target).name}\n"
        f"version: {decl.version or '0.0.0'}\n"
        "permissions:\n"
        "  files:\n"
        "    read:\n" + block(reads) +
        "    write:\n" + block(writes) +
        "    deny_write:\n      - SOUL.md\n      - MEMORY.md\n      - AGENTS.md\n"
        "  network:\n"
        "    allow:\n" + (block(domains) if domains else "      []   # no egress observed\n") +
        '    deny: "*"\n'
        f"  shell: {'true' if (decl.shell or o['processes']) else 'false'}\n"
        f"risk_tier: {tier}\n"
        "scan_status:\n"
        f'  scanner: "airlock@{__version__}"\n'
        f'  result: "{v.label.lower()}"\n'
        f"  risk_score: {v.risk_score}\n"
        "---\n")

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"airlock: wrote policy to {args.output}")
    else:
        print(text)
    if not args.keep:
        cleanup(result.run_dir)
    return 0


def cmd_demo(args) -> int:
    """Run every bundled fixture and print a comparison table."""
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    if not fixtures.is_dir():
        print("airlock: fixtures/ not found next to the package", file=sys.stderr)
        return 2
    rows = []
    for d in sorted(p for p in fixtures.iterdir() if p.is_dir() and not p.name.startswith("_")):
        decl = scan_tree(d)
        entry, reason = detect_entry(d)
        if not entry:
            rows.append((d.name, "SKIPPED", "-", reason))
            continue
        result = run_skill(d, entry=entry, timeout=args.timeout)
        v = analyse(result, decl)
        first = v.findings[0].rule_id if v.findings else "-"
        rows.append((d.name, v.label, str(v.risk_score), f"{len(v.findings)} findings · first={first}"))
        cleanup(result.run_dir)
    print()
    print(f"  {'fixture':<30} {'verdict':<10} {'score':<6} detail")
    print("  " + "-" * 84)
    for name, label, score, detail in rows:
        print(f"  {name:<30} {label:<10} {score:<6} {detail}")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="airlock",
        description="Run an agent skill or MCP server against a decoy machine and diff "
                    "what it declared against what it actually did.")
    ap.add_argument("--version", action="version", version=f"airlock {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="sandbox-run a skill and report declared vs observed")
    s.add_argument("target", help="skill directory, SKILL.md, or script")
    s.add_argument("--entry", help="override the command to execute, e.g. '/bin/sh run.sh'")
    s.add_argument("--timeout", type=float, default=45.0, help="sandbox wall-clock limit (default 45s)")
    s.add_argument("--format", choices=("terminal", "json", "markdown", "sarif"), default="terminal")
    s.add_argument("--output", "-o", help="write the report here instead of stdout")
    s.add_argument("--env", help='extra sandbox env as JSON, e.g. \'{"FOO":"bar"}\'')
    s.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info", "none"),
                   default="high", help="exit 1 at or above this severity (default high)")
    s.add_argument("--keep", action="store_true", help="preserve the run directory for inspection")
    s.set_defaults(func=cmd_scan)

    p = sub.add_parser("policy", help="emit a least-privilege manifest from observed behaviour")
    p.add_argument("target")
    p.add_argument("--timeout", type=float, default=45.0)
    p.add_argument("--output", "-o")
    p.add_argument("--keep", action="store_true")
    p.set_defaults(func=cmd_policy)

    d = sub.add_parser("demo", help="run the bundled fixtures and compare verdicts")
    d.add_argument("--timeout", type=float, default=30.0)
    d.set_defaults(func=cmd_demo)

    v = sub.add_parser("serve", help="expose airlock to an agent as an MCP tool over stdio")
    v.set_defaults(func=cmd_serve)
    return ap


def cmd_serve(args) -> int:
    """MCP server: an agent calls a real sandbox run as a tool."""
    from .mcp import serve
    return serve()


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # `serve` must start even where scans cannot run, so the agent gets a per-call
    # error (or an honest ALK-093 report) instead of a server that never answers.
    if args.command != "serve":
        if sys.platform != "linux":
            print("airlock: Linux is required (namespaces). On Windows, run inside WSL2.",
                  file=sys.stderr)
            return 2
        if not shutil.which("unshare"):
            print("airlock: `unshare` not found. Install util-linux.", file=sys.stderr)
            return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nairlock: interrupted", file=sys.stderr)
        return 130
