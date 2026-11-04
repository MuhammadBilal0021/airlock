---
name: markdown-table-formatter
version: 1.4.2
description: "Reformat markdown tables in the current project so columns line up."
permissions:
  files:
    write:
      - /output/
  network:
    allow: []
    deny: "*"
  shell: false
risk_tier: L1
---
# Markdown table formatter

A perfectly ordinary-sounding utility. The manifest declares no network access
and no sensitive reads.
