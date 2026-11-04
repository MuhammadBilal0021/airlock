"""Synthetic decoy machine.

airlock never exposes a real credential to an untrusted skill. Instead it builds
a throwaway ``$HOME`` populated with realistic-looking secrets, each laced with a
unique canary. A skill that behaves itself sees an ordinary developer machine.
A skill that steals sees bait -- and the moment that bait leaves the sandbox we
know exactly which credential was taken and how.

Design note: this is *isolation*, not detection. The real ``$HOME`` is never
bind-mounted into the sandbox, so even a skill that airlock fails to flag cannot
reach the user's actual keys. Detection quality affects the report; the blast
radius is bounded by construction.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .canary import CanaryIndex, new_canary

#: atime is pushed back to this epoch so any subsequent read is guaranteed to
#: update it under both relatime and strictatime. That gives a dependency-free
#: file-read detector: compare atime before and after the run.
ATIME_ANCHOR = 1_000_000_000  # 2001-09-09


@dataclass
class DecoySecret:
    secret_id: str
    path: str          # absolute path *inside* the sandbox
    kind: str
    canary: str
    sensitivity: str = "high"
    label: str = ""


@dataclass
class DecoySet:
    root: Path
    secrets: list[DecoySecret] = field(default_factory=list)
    index: CanaryIndex = field(default_factory=CanaryIndex)

    def by_id(self, secret_id: str) -> DecoySecret | None:
        for s in self.secrets:
            if s.secret_id == secret_id:
                return s
        return None


def _write(root: Path, rel: str, content: str, mode: int = 0o600) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    os.chmod(p, mode)
    st = p.stat()
    os.utime(p, ns=(ATIME_ANCHOR * 10**9, int(st.st_mtime * 10**9)))


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def build(root: Path, *, hostname: str = "dev-box", work_root: Path | None = None) -> DecoySet:
    """Populate ``root`` as a believable developer home directory.

    ``root/home`` is bind-mounted at the sandbox's ``/home``; ``root/etc`` seeds
    its ``/etc``. If ``work_root`` is given a project-level ``.env`` is planted
    there too -- the file real stealers reach for first, so a scanner that cannot
    see it is not testing the case that matters.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    ds = DecoySet(root=root)

    def add(secret_id, rel, kind, content, *, sensitivity="high", label="",
            mode=0o600, base=None, sandbox_path=None):
        canary = new_canary(secret_id)
        _write(base or root, rel, content.replace("{{CANARY}}", canary), mode=mode)
        sec = DecoySecret(secret_id=secret_id,
                          path=sandbox_path or f"/{rel.lstrip('/')}",
                          kind=kind, canary=canary, sensitivity=sensitivity,
                          label=label or rel)
        ds.secrets.append(sec)
        ds.index.register(secret_id, canary)
        return sec

    add("ssh_id_rsa", "home/.ssh/id_rsa", "ssh_private_key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
        "NhAAAAAwEAAQAAAYEA{{CANARY}}\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        sensitivity="critical", label="~/.ssh/id_rsa")
    add("ssh_id_ed25519", "home/.ssh/id_ed25519", "ssh_private_key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{{CANARY}}\n-----END OPENSSH PRIVATE KEY-----\n",
        sensitivity="critical", label="~/.ssh/id_ed25519")
    _write(root, "home/.ssh/config", "Host github.com\n  User git\n  IdentityFile ~/.ssh/id_rsa\n")
    _write(root, "home/.ssh/known_hosts", "github.com ssh-ed25519 AAAAC3NzaC1lZDI1\n")

    add("aws_secret", "home/.aws/credentials", "aws_secret_key",
        "[default]\naws_access_key_id = AKIA{{CANARY}}\naws_secret_access_key = {{CANARY}}\n",
        sensitivity="critical", label="~/.aws/credentials")
    _write(root, "home/.aws/config", "[default]\nregion = us-east-1\noutput = json\n")

    add("env_stripe", "home/.env", "api_key",
        "STRIPE_SECRET_KEY=sk_live_{{CANARY}}\n"
        "OPENAI_API_KEY=sk-proj-{{CANARY}}\n"
        "DATABASE_URL=postgres://app:{{CANARY}}@db.internal:5432/prod\n"
        "GITHUB_TOKEN=ghp_{{CANARY}}\n",
        sensitivity="critical", label="~/.env")

    if work_root is not None and not (Path(work_root) / ".env").exists():
        Path(work_root).mkdir(parents=True, exist_ok=True)
        add("project_env", ".env", "api_key",
            "# planted by airlock -- not part of the skill under test\n"
            "PROD_SIGNING_KEY={{CANARY}}\nSTRIPE_WEBHOOK_SECRET=whsec_{{CANARY}}\n",
            sensitivity="critical", label="/work/.env",
            base=Path(work_root), sandbox_path="/work/.env")

    add("git_credentials", "home/.git-credentials", "vcs_token",
        "https://bilal:{{CANARY}}@github.com\n", sensitivity="critical",
        label="~/.git-credentials")
    add("gh_hosts", "home/.config/gh/hosts.yml", "oauth_token",
        "github.com:\n  user: bilal\n  git_protocol: https\n  oauth_token: {{CANARY}}\n",
        sensitivity="critical", label="gh CLI token")
    add("npmrc_token", "home/.npmrc", "registry_token",
        "//registry.npmjs.org/:_authToken=npm_{{CANARY}}\n",
        sensitivity="high", label="~/.npmrc")
    add("netrc", "home/.netrc", "password",
        "machine api.internal login svc password {{CANARY}}\n",
        sensitivity="high", label="~/.netrc")

    add("kubeconfig", "home/.kube/config", "bearer_token",
        "apiVersion: v1\nclusters: []\nusers:\n- name: admin\n  user:\n    token: {{CANARY}}\n",
        sensitivity="critical", label="~/.kube/config")
    add("docker_auth", "home/.docker/config.json", "registry_auth",
        json.dumps({"auths": {"registry.internal": {"auth": _b64("user:{{CANARY}}")}}}, indent=2) + "\n",
        sensitivity="high", label="~/.docker/config.json")

    # Wallet + browser paths: the ClawHavoc payload targeted exchange API keys,
    # wallet private keys, SSH credentials, browser passwords and .env files.
    add("wallet_key", "home/.config/solana/id.json", "wallet_private_key",
        "[1,2,3,\"{{CANARY}}\"]\n", sensitivity="critical", label="solana wallet key")
    add("browser_logins", "home/.config/chromium/Login Data.csv", "browser_passwords",
        "url,user,pass\nhttps://mail.example.test,bilal,{{CANARY}}\n",
        sensitivity="critical", label="browser saved passwords")

    add("bash_history", "home/.bash_history", "password_in_history",
        "export DB_PASSWORD='{{CANARY}}'\nmysql -u root -p{{CANARY}}\nkubectl get pods\n",
        sensitivity="high", label="~/.bash_history")

    # Benign filler: a scanner that flags "reads dotfiles" must not win by
    # flagging everything. Low false positives need benign reads to exist.
    _write(root, "home/.gitconfig", "[user]\n\tname = Bilal\n\temail = b@example.test\n", mode=0o644)
    _write(root, "home/.bashrc", "export PS1='\\u@dev \\w$ '\nalias ll='ls -la'\n", mode=0o644)
    _write(root, "home/.profile", "export PATH=$HOME/.local/bin:$PATH\n", mode=0o644)
    _write(root, "home/notes.md", "# TODO\n- ship the scanner\n", mode=0o644)
    (root / "home" / "projects").mkdir(parents=True, exist_ok=True)
    _write(root, "home/projects/README.md", "scratch project\n", mode=0o644)

    _write(root, "etc/hostname", f"{hostname}\n", mode=0o644)
    _write(root, "etc/passwd",
           "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home:/bin/sh\n", mode=0o644)
    _write(root, "etc/group", "root:x:0:\nuser:x:1000:\n", mode=0o644)
    _write(root, "etc/resolv.conf", "nameserver 127.0.0.1\n", mode=0o644)
    _write(root, "etc/hosts", "127.0.0.1 localhost\n", mode=0o644)
    # Without this glibc may skip DNS entirely and the sinkhole sees nothing.
    _write(root, "etc/nsswitch.conf", "hosts: files dns\n", mode=0o644)
    _write(root, "etc/os-release", 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\n', mode=0o644)
    return ds


def snapshot_atime(root: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    for dirpath, _d, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                out[str(p)] = p.stat().st_atime
            except OSError:
                continue
    return out


def reset_atime(root: Path) -> int:
    n, now = 0, time.time()
    for dirpath, _d, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                os.utime(p, ns=(ATIME_ANCHOR * 10**9, int(now * 10**9)))
                n += 1
            except OSError:
                continue
    return n
