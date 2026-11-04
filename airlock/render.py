"""Terminal and Markdown rendering.

The terminal view is the artefact that has to survive being screenshotted and
pasted into a pull request, so it leads with the declared/observed contrast
rather than a wall of log lines.
"""

from __future__ import annotations

import os
import sys

from .engine import Verdict

_SEV_SYMBOL = {"critical": "!!", "high": "! ", "medium": "+ ", "low": "- ", "info": "i "}


class C:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def green(self, s): return self._w("32", s)
    def cyan(self, s): return self._w("36", s)
    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)
    def magenta(self, s): return self._w("35", s)

    def sev(self, severity, s=""):
        target = s or severity.upper()
        fn = {"critical": self.red, "high": self.red, "medium": self.yellow,
              "low": self.cyan, "info": self.dim}.get(severity)
        return fn(target) if fn else target


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("AIRLOCK_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def render_terminal(v: Verdict, target: str, *, width: int = 96) -> str:
    c = C(_color_enabled())
    L, rule = [], c.dim("-" * min(width, 78))
    cov, d, o = v.coverage, v.declared, v.observed_summary

    L += ["", f"  {c.bold('airlock')}  {c.dim('behavioural sandbox for agent skills & MCP servers')}", rule]
    L.append(f"  {c.bold('target')}    {target}")
    L.append(f"  {c.bold('runtime')}   {o['duration_s']}s · exit {o['exit_code']}"
             f" · ns: {cov.get('namespace_flags', '?')}")
    L.append(f"  {c.bold('coverage')}  proc={cov.get('proc', '?')}"
             f" · process tree {'sampled' if cov.get('process_tree') else 'NOT sampled'}"
             f" · network {'isolated' if cov.get('network_isolated') else 'NOT isolated'}")
    for err in cov.get("errors", []):
        L.append(f"            {c.yellow('warn:')} {err[:width - 14]}")

    L += ["", f"  {c.cyan(c.bold('DECLARED'))}  "
              f"{c.dim('(' + (', '.join(d.manifests_found) or 'no manifest found') + ')')}"]
    L.append(f"    read     {', '.join(d.fs_read) or c.dim('(nothing)')}")
    L.append(f"    write    {', '.join(d.fs_write) or c.dim('(nothing)')}")
    net = ', '.join(d.net_allow) if d.net_allow else ("any" if d.net_declared_any else "(none)")
    L.append(f"    network  {net}")
    L.append(f"    shell    " + (
        ("yes" if d.shell else "no") if d.shell is not None else c.dim("undeclared")))
    if d.tools:
        L.append(f"    tools    {', '.join(d.tools[:8])}")

    L += ["", f"  {c.magenta(c.bold('OBSERVED'))}  "
              f"{c.dim('(decoy machine, no route to the internet)')}"]
    if o.get("ambient_reads_suppressed"):
        L.append(f"    {c.dim('(suppressed ' + str(len(o['ambient_reads_suppressed'])) + ' ambient libc/interpreter reads: ' + ', '.join(o['ambient_reads_suppressed'][:3]) + ')')}")
    for label, items in (("read", o["files_read"]), ("write", o["files_written"]),
                         ("dns", o["dns_queries"]), ("net", o["domains"]),
                         ("procs", o["processes"])):
        if not items:
            continue
        shown = items[:6]
        more = c.dim(f"   +{len(items) - len(shown)} more") if len(items) > 6 else ""
        L.append(f"    {label:<7}  {shown[0]}{more}")
        for extra in shown[1:]:
            L.append(f"             {extra}")

    L.append("")
    if not v.findings:
        L.append(f"  {c.green(c.bold('NO FINDINGS'))}")
        L.append(c.dim("    Nothing crossed the declared boundary. A clean run proves only"))
        L.append(c.dim("    that nothing fired in this window, on these inputs."))
    else:
        L.append(f"  {c.bold('FINDINGS')} {c.dim(f'({len(v.findings)})')}")
        for f in v.findings:
            L.append(f"    {c.sev(f.severity, _SEV_SYMBOL.get(f.severity, '? '))} "
                     f"{c.sev(f.severity, f.severity.upper()):<19} "
                     f"{c.bold(f.rule_id)} {c.dim(f.ast)}  {f.title}")
            for ev in f.evidence[:3]:
                L.append(f"        {c.dim('·')} {str(ev)[:width - 12]}")
            if f.declared or f.observed:
                L.append(c.dim(f"        declared: {f.declared or '-'}"))
                L.append(c.dim(f"        observed: {f.observed or '-'}"))
            if f.confidence == "heuristic":
                L.append(c.dim("        confidence: heuristic -- a reason to look, not proof"))

    t = v.trifecta
    mark = lambda ok: c.green("yes") if ok else c.dim("no")  # noqa: E731
    L += ["", rule,
          f"  {c.bold('VERDICT')}   " + (
              {"CRITICAL": c.red, "HIGH": c.red, "ELEVATED": c.yellow,
               "LOW": c.cyan, "CLEAN": c.green}.get(v.label, c.dim)(v.label))
          + f"   {c.bold(f'risk score {v.risk_score}/100')}",
          f"  {c.bold('lethal trifecta')}",
          f"    private data       {mark(bool(t['private_data_access']))}",
          f"    untrusted content  {mark(bool(t['untrusted_content']))}",
          f"    external comms     {mark(bool(t['external_communication']))}"]
    if t["satisfied"]:
        L.append(c.red("    => all three legs present: this skill can be weaponised by anything it reads"))
    L.append("")
    return "\n".join(L)


def render_markdown(v: Verdict, target: str, *, version: str = "0.1.0") -> str:
    d, o = v.declared, v.observed_summary
    yesno = lambda b: "yes" if b else "no"  # noqa: E731
    out = [
        f"# airlock report — `{target}`", "",
        f"**Verdict: {v.label}** · risk score **{v.risk_score}/100** · "
        f"{len(v.findings)} finding(s) · scanned by airlock {version}", "",
        "## Scope", "",
        "| | declared | observed |", "|---|---|---|",
        f"| file reads | {', '.join(d.fs_read) or '—'} | {', '.join(o['files_read']) or '—'} |",
        f"| file writes | {', '.join(d.fs_write) or '—'} | {', '.join(o['files_written']) or '—'} |",
        f"| network | {', '.join(d.net_allow) or ('any' if d.net_declared_any else '—')} | {', '.join(o['domains']) or '—'} |",
        f"| DNS | — | {', '.join(o['dns_queries']) or '—'} |",
        f"| processes | — | {len(o['processes'])} |", "",
        f"Run took {o['duration_s']}s, exit code `{o['exit_code']}`. "
        f"Namespaces: `{v.coverage.get('namespace_flags')}`. `/proc` mode: `{v.coverage.get('proc')}`.", "",
        "## Lethal Trifecta", "",
        "| leg | satisfied | evidence |", "|---|---|---|",
        f"| access to private data | {yesno(v.trifecta['private_data_access'])} | "
        f"{', '.join(v.trifecta['private_data_access'][:4]) or '—'} |",
        f"| exposure to untrusted content | {yesno(v.trifecta['untrusted_content'])} | "
        f"{', '.join(str(x) for x in v.trifecta['untrusted_content'][:4]) or '—'} |",
        f"| ability to communicate externally | {yesno(v.trifecta['external_communication'])} | "
        f"{', '.join(v.trifecta['external_communication'][:4]) or '—'} |", "",
        "## Findings", "",
    ]
    if not v.findings:
        out += ["_No findings._ A clean run proves only that nothing fired within this window on "
                "these inputs; it does not prove absence of conditional or delayed behaviour.", ""]
    for f in v.findings:
        out += [f"### `{f.rule_id}` · {f.severity.upper()} · {f.title}", "",
                f"*OWASP AST10 mapping: **{f.ast}*** · confidence: {f.confidence}", "",
                f.detail, ""]
        if f.evidence:
            out += ["**Evidence**", ""] + [f"- `{e}`" for e in f.evidence[:8]] + [""]
        if f.declared or f.observed:
            out += [f"- declared: `{f.declared or '—'}`", f"- observed: `{f.observed or '—'}`", ""]
    out += [
        "## How to read this", "",
        "airlock ran the skill inside a user/mount/network/PID namespace against a synthetic "
        "home directory containing canary-laced credentials, with no route to the internet. "
        "Findings marked *confirmed* rest on an observed artefact — a canary string in captured "
        "traffic, an atime delta, a file on disk. Findings marked *heuristic* are inferred from "
        "text and should be reviewed by a human.", "",
        "A clean result is not a proof of safety. Behaviour gated on a credential, a date, or an "
        "input this run did not supply would not have fired.", "",
        "---", f"_Generated by [airlock](https://github.com/MuhammadBilal0021/airlock) {version}._",
    ]
    return "\n".join(out)
