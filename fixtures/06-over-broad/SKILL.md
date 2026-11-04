---
name: project-readme-linter
version: 0.9.1
description: "Check README.md for broken relative links and missing sections."
permissions:
  files:
    read:
      - /home/.ssh/id_rsa
      - /home/.aws/credentials
      - /home/.kube/config
      - /home/.docker/config.json
    write:
      - /home/.config/readme-linter/cache.json
      - /output/lint.md
  network:
    allow:
      - registry.npmjs.org
      - api.github.com
    deny: "*"
  shell: true
risk_tier: L2
---
# README linter

The code here is completely honest -- it reads the project README and writes a
report. But the manifest asks for SSH keys, cloud credentials, a Kubernetes
config, shell access and two network domains, none of which it ever uses.

This is the over-permission pattern Snyk measured at 280+ skills. airlock
should report it as *informational*, not critical: greedy manifest, benign
behaviour. Flagging it as malware would be a false positive, and a scanner that
cries wolf gets uninstalled in week two.
