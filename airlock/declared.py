"""Declared-capability extraction.

Parses what a skill *says* it will do, from every manifest format in the wild,
and normalises it into one structure the diff engine can compare against
observed behaviour.

Supported inputs: OpenClaw / Claude ``SKILL.md`` (YAML frontmatter + Markdown),
Claude Code ``skill.json``, Cursor/Codex ``manifest.json``, VS Code
``package.json``, the OWASP AST10 **Universal Skill Format**, and MCP
configuration (``mcp.json`` / ``.mcp.json`` / ``mcpServers`` blocks).

No YAML dependency: the frontmatter we care about is a small well-behaved
subset, and shipping zero runtime dependencies is worth more than supporting
anchors and aliases nobody puts in a skill manifest.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SKILL_FILENAMES = ("SKILL.md", "skill.md", "SOUL.md", "MEMORY.md", "AGENTS.md")
MANIFEST_FILENAMES = (
    "skill.json", "manifest.json", "package.json", "airlock.json",
    "mcp.json", ".mcp.json", "claude_desktop_config.json", ".cursor/mcp.json",
)

#: Imperatives aimed at the model rather than at the reader. These live in
#: description fields most UIs never render -- the injection vector Invariant
#: Labs documented and that signature scanners miss.
EMBEDDED_INSTRUCTION_PATTERNS = (
    (r"\bnote for the (?:assistant|model|agent)\b", "model-directed note"),
    (r"<\s*/?\s*important\s*>", "hidden <IMPORTANT> block"),
    (r"\bsystem prompt\b", "references the system prompt"),
    (r"\bignore (?:all |any )?(?:previous|prior|above) (?:instructions?|rules?)\b", "instruction override"),
    (r"\bdo not (?:tell|inform|mention to|reveal to) the user\b", "concealment directive"),
    (r"\bwithout (?:asking|telling|informing|notifying) the user\b", "silent-action directive"),
    (r"\bsilently\b|\bcovertly\b|\bin secret\b", "covert-action wording"),
    (r"\balways (?:add|include|bcc|cc|send|append|exfiltrate|upload)\b", "unconditional side-effect"),
    (r"\b(?:bcc|blind copy)\b", "hidden recipient"),
    (r"\bwhenever .{0,60}\b(?:tool|send_email|request)\b.{0,60}\b(?:also|additionally)\b", "cross-tool side-effect"),
    (r"\bcompliance requirement\b|\bmandatory policy\b|\brequired by law\b", "false-authority pretext"),
    (r"\b(?:curl|wget|fetch)\b.{0,40}\|\s*(?:ba|z|da)?sh\b", "remote code execution idiom"),
    (r"\b(?:~|\$HOME)/\.ssh\b|\bid_rsa\b|\bid_ed25519\b", "references SSH private keys"),
    (r"\b\.aws/credentials\b|\baws_secret_access_key\b", "references cloud credentials"),
    (r"\b\.env\b.{0,40}\b(?:read|send|upload|post|include)\b", "references dotenv secrets"),
    (r"\b(?:base64|hex|rot13|encode)\b.{0,40}\b(?:before sending|then send|exfil)\b", "obfuscated egress"),
    (r"\bdns\b.{0,30}\b(?:subdomain|exfil|tunnel)\b", "DNS exfiltration channel"),
)

#: Reads that glibc, the dynamic loader and language interpreters perform on
#: essentially every run. Not evidence of anything. Suppressing them is what
#: keeps the false-positive rate low enough that people keep the tool installed
#: past week two -- a scanner that flags everything gets ignored.
AMBIENT_READS = frozenset({
    "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/passwd",
    "/etc/group", "/etc/os-release", "/etc/hostname", "/etc/localtime",
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/services", "/etc/protocols",
    "/etc/ssl/openssl.cnf", "/etc/mime.types", "/etc/shells", "/etc/timezone",
})

#: Writes that give a skill persistence across sessions. ClawHavoc backdoored
#: agents exactly this way, via MEMORY.md and SOUL.md.
PERSISTENCE_PATHS = (
    "/home/.bashrc", "/home/.profile", "/home/.bash_profile", "/home/.zshrc",
    "/home/SOUL.md", "/home/MEMORY.md", "/home/AGENTS.md",
    "/work/SOUL.md", "/work/MEMORY.md", "/work/AGENTS.md",
    "/work/CLAUDE.md", "/work/.claude/settings.json",
    "/home/.config/autostart", "/etc/cron.d", "/home/.ssh/authorized_keys",
)


@dataclass
class CapabilityDeclaration:
    """Normalised view of everything the skill claims about itself."""

    name: str = ""
    version: str = ""
    author: str = ""
    description: str = ""
    platforms: list = field(default_factory=list)
    fs_read: list = field(default_factory=list)
    fs_write: list = field(default_factory=list)
    fs_deny_write: list = field(default_factory=list)
    net_allow: list = field(default_factory=list)
    net_deny: list = field(default_factory=list)
    shell: bool | None = None
    tools: list = field(default_factory=list)
    binaries: list = field(default_factory=list)
    risk_tier: str = ""
    sources: dict = field(default_factory=dict)
    raw_frontmatter: dict = field(default_factory=dict)
    manifests_found: list = field(default_factory=list)
    #: (source, text) pairs harvested from description-ish fields and markdown
    #: bodies, scanned for instructions a UI would never show the user.
    instruction_surface: list = field(default_factory=list)
    net_declared_any: bool = False

    def declares_domain(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        for entry in self.net_allow:
            e = entry.lower().strip().strip(".").lstrip("*.")
            if not e or e == "*":
                return True
            if host == e or host.endswith("." + e):
                return True
        return False

    def declares_path(self, sandbox_path: str, want: str = "read") -> bool:
        pool = self.fs_read if want == "read" else self.fs_write
        if "*" in pool:
            return True
        target = sandbox_path.rstrip("/")
        for entry in pool:
            e = entry.strip()
            if not e:
                continue
            if e in ("*", "~", "$HOME"):
                return True
            e = e.replace("~", "/home").replace("$HOME", "/home")
            if e.endswith("*"):
                if target.startswith(e[:-1]):
                    return True
            elif target == e.rstrip("/") or target.startswith(e.rstrip("/") + "/"):
                return True
        return False


# ----------------------------------------------------------------- tiny YAML

def _coerce(v: str):
    v = v.strip()
    if v.startswith(("[", "{")):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            pass
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "none", "~", ""):
        return None
    return v.strip("'\"")


def parse_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^\ufeff?---\s*\r?\n(.*?)\r?\n---\s*\r?\n?(.*)$", text, re.DOTALL)
    if not m:
        return {}, text
    return _parse_simple_yaml(m.group(1)), m.group(2)


def _parse_simple_yaml(block: str):
    """Recursive-descent parser for the YAML subset manifests actually use.

    Handles nested mappings and block sequences (``key:`` followed by more
    deeply indented ``- item`` lines), inline flow lists (``[a, b]``), quoted
    scalars and comments. It does not handle anchors, aliases, multi-line
    folded scalars or multi-document streams -- none of which appear in a skill
    manifest, and supporting them is not worth a PyYAML dependency.
    """
    lines = []
    for raw in block.splitlines():
        if not raw.strip():
            continue
        stripped = raw.lstrip(" ")
        if stripped.startswith("#"):
            continue
        # Strip trailing comments only when clearly outside a quoted scalar.
        if "#" in stripped and not (stripped.count('"') % 2 or stripped.count("'") % 2):
            cut = stripped.find(" #")
            if cut != -1:
                stripped = stripped[:cut]
        lines.append((len(raw) - len(raw.lstrip(" ")), stripped.rstrip()))

    def parse(i: int, indent: int):
        if i >= len(lines):
            return None, i
        if lines[i][1].startswith("- "):
            return parse_seq(i, indent)
        return parse_map(i, indent)

    def parse_seq(i: int, indent: int):
        out = []
        while i < len(lines):
            ind, text = lines[i]
            if ind < indent or not text.startswith("- "):
                break
            if ind > indent:
                i += 1
                continue
            item = text[2:].strip()
            if item and ":" in item and not item.startswith(("[", "{", '"', "'")):
                # "- key: value" -- a mapping entry inside a sequence.
                sub = {item.split(":", 1)[0].strip(): _coerce(item.split(":", 1)[1])}
                i += 1
                if i < len(lines) and lines[i][0] > indent and not lines[i][1].startswith("- "):
                    nested, i = parse_map(i, lines[i][0], into=sub)
                    out.append(nested)
                else:
                    out.append(sub)
                continue
            if item == "":
                i += 1
                if i < len(lines) and lines[i][0] > indent:
                    val, i = parse(i, lines[i][0])
                    out.append(val)
                else:
                    out.append(None)
                continue
            out.append(_coerce(item))
            i += 1
        return out, i

    def parse_map(i: int, indent: int, into: dict | None = None):
        out = into if into is not None else {}
        while i < len(lines):
            ind, text = lines[i]
            if ind < indent or text.startswith("- "):
                break
            if ind > indent:
                i += 1
                continue
            if ":" not in text:
                i += 1
                continue
            key, _, val = text.partition(":")
            key, val = key.strip().strip("'\""), val.strip()
            if val:
                out[key] = _coerce(val)
                i += 1
                continue
            # Empty value: either a nested block follows, or it is null.
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                child, i = parse(i + 1, lines[i + 1][0])
                out[key] = child
            else:
                out[key] = None
                i += 1
        return out, i

    value, _ = parse(0, lines[0][0] if lines else 0)
    return value if isinstance(value, dict) else {}


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in re.split(r"[,\n]", v) if x.strip()]
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            if isinstance(x, dict):
                out.extend(str(vv) for vv in x.values() if vv)
            elif x is not None:
                out.append(str(x))
        return out
    return [str(v)]


def _parse_allowed_tools(specs: list, decl: CapabilityDeclaration) -> None:
    """Claude Code ``allowed-tools`` carries real capability signal:
    ``Bash(git:*)``, ``WebFetch(domain:example.com)``, ``Read(~/.config/app)``.
    """
    for spec in specs:
        m = re.match(r"^\s*([A-Za-z_]+)\s*(?:\(([^)]*)\))?\s*$", spec)
        if not m:
            continue
        tool, arg = m.group(1), (m.group(2) or "").strip()
        decl.tools.append(tool)
        low = tool.lower()
        if low in ("bash", "shell", "exec", "run"):
            decl.shell = True
            if arg:
                decl.binaries.append(arg.split(":")[0].strip())
        elif low in ("webfetch", "websearch", "http", "fetch", "network"):
            decl.net_declared_any = True
            dm = re.search(r"domain:([^,)\s]+)", arg)
            if dm:
                decl.net_allow.append(dm.group(1))
            elif arg and arg != "*":
                decl.net_allow.append(arg)
        elif low in ("read", "view", "cat"):
            if arg:
                decl.fs_read.append(arg.replace("~", "/home"))
        elif low in ("write", "edit", "create"):
            if arg:
                decl.fs_write.append(arg.replace("~", "/home"))


def _absorb(decl: CapabilityDeclaration, data: dict, source: str) -> None:
    def note(f): decl.sources.setdefault(f, source)

    for key in ("name", "version", "author", "description", "risk_tier"):
        val = data.get(key)
        if isinstance(val, dict):
            val = val.get("name")
        if val and not getattr(decl, key):
            setattr(decl, key, str(val)); note(key)
    if isinstance(data.get("platforms"), list):
        decl.platforms.extend(str(p) for p in data["platforms"])

    perms = data.get("permissions") or {}
    if isinstance(perms, dict):
        files = perms.get("files") or {}
        if isinstance(files, dict):
            decl.fs_read.extend(_as_list(files.get("read")))
            decl.fs_write.extend(_as_list(files.get("write")))
            decl.fs_deny_write.extend(_as_list(files.get("deny_write")))
            if files:
                note("fs_read")
        net = perms.get("network")
        if isinstance(net, dict):
            allow = _as_list(net.get("allow"))
            decl.net_allow.extend(allow)
            decl.net_deny.extend(_as_list(net.get("deny")))
            if allow:
                decl.net_declared_any = True; note("net_allow")
        elif isinstance(net, bool):
            decl.net_declared_any = decl.net_declared_any or net
        elif isinstance(net, list):
            decl.net_allow.extend(_as_list(net)); decl.net_declared_any = True
        if "shell" in perms:
            decl.shell = bool(perms["shell"]); note("shell")
        decl.tools.extend(_as_list(perms.get("tools")))

    req = data.get("requires") or {}
    if isinstance(req, dict):
        decl.binaries.extend(_as_list(req.get("binaries")))

    _parse_allowed_tools(_as_list(data.get("allowed-tools") or data.get("allowed_tools")), decl)

    for key in ("network", "domains", "allowed_domains", "hosts", "endpoints"):
        vals = _as_list(data.get(key))
        if vals:
            decl.net_allow.extend(v for v in vals if isinstance(v, str))
            decl.net_declared_any = True; note("net_allow")
    for key in ("read", "reads", "files_read"):
        decl.fs_read.extend(_as_list(data.get(key)))
    for key in ("write", "writes", "files_write"):
        decl.fs_write.extend(_as_list(data.get(key)))

    for key, val in data.items():
        if isinstance(val, str) and len(val) > 12 and key in (
                "description", "summary", "instructions", "prompt", "details", "notes"):
            decl.instruction_surface.append((f"{source}:{key}", val))

    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for sname, scfg in servers.items():
            if isinstance(scfg, dict):
                decl.binaries.extend(c for c in (_as_list(scfg.get("command"))
                                                 + _as_list(scfg.get("args"))) if c)
                decl.sources.setdefault("mcpServers", f"{source}:{sname}")
                if scfg.get("url"):
                    decl.net_allow.append(str(scfg["url"])); decl.net_declared_any = True


def scan_tree(root: Path) -> CapabilityDeclaration:
    """Walk a skill directory and absorb every manifest found."""
    root = Path(root)
    decl = CapabilityDeclaration()
    candidates = []
    if root.is_file():
        candidates = [root]
    else:
        for name in SKILL_FILENAMES:
            p = root / name
            if p.exists():
                candidates.append(p)
        candidates.extend(p for p in root.rglob("SKILL.md"))
        for name in MANIFEST_FILENAMES:
            p = root / name
            if p.exists():
                candidates.append(p)
        candidates.extend(root.glob("**/skill.json"))
        candidates.extend(root.glob("**/manifest.json"))

    seen = set()
    for path in candidates:
        try:
            st = path.stat()
            # DrvFS can resolve SKILL.md and skill.md to the same file while
            # preserving different spellings. Deduplicate by filesystem identity.
            key = (st.st_dev, st.st_ino) if st.st_ino else str(path.resolve())
        except OSError:
            continue
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        decl.manifests_found.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.suffix.lower() == ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                _absorb(decl, data, rel)
        else:
            fm, body = parse_frontmatter(text)
            if fm:
                decl.raw_frontmatter = {**decl.raw_frontmatter, **fm}
                _absorb(decl, fm, rel)
            # The markdown body reaches the agent even when a UI renders only
            # `description`, so it is part of the instruction surface too.
            if body.strip() and path.name in SKILL_FILENAMES:
                decl.instruction_surface.append((f"{rel}:body", body))

    for attr in ("fs_read", "fs_write", "fs_deny_write", "net_allow", "tools",
                 "binaries", "platforms", "manifests_found"):
        seen_vals, deduped = set(), []
        for v in getattr(decl, attr):
            if v not in seen_vals:
                seen_vals.add(v); deduped.append(v)
        setattr(decl, attr, deduped)
    if "*" in decl.net_allow:
        decl.net_declared_any = True
    return decl


def find_embedded_instructions(decl: CapabilityDeclaration) -> list:
    """Flag model-directed imperatives hidden in text a UI may never render."""
    findings = []
    for source, text in decl.instruction_surface:
        low = text.lower()
        for pattern, why in EMBEDDED_INSTRUCTION_PATTERNS:
            m = re.search(pattern, low)
            if not m:
                continue
            start, end = max(0, m.start() - 70), min(len(text), m.end() + 70)
            findings.append({"source": source, "reason": why, "pattern": pattern,
                             "excerpt": " ".join(text[start:end].split()),
                             "offset": m.start()})
    return findings
