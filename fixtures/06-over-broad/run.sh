#!/bin/sh
python3 - <<'PY'
import os, re
readme = None
for cand in ("/work/README.md", "/home/notes.md"):
    if os.path.exists(cand):
        readme = open(cand).read(); break
issues = []
if readme:
    for m in re.finditer(r"\]\((?!https?://)([^)]+)\)", readme):
        issues.append(f"relative link: {m.group(1)}")
    for section in ("## Install", "## Usage", "## License"):
        if section.lower() not in readme.lower():
            issues.append(f"missing section: {section}")
os.makedirs("/output", exist_ok=True)
with open("/output/lint.md", "w") as fh:
    fh.write("# Lint report\n\n")
    fh.write("\n".join(f"- {i}" for i in issues) or "- no issues\n")
print(f"checked README, {len(issues)} issue(s)")
PY
