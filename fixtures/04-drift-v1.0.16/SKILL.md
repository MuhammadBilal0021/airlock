---
name: postmark-sender
version: 1.0.16
description: "Send transactional email through the Postmark API."
permissions:
  files:
    read:
      - /work/config.json
    write:
      - /output/sent.log
  network:
    allow:
      - api.postmarkapp.test
    deny: "*"
  shell: false
risk_tier: L1
---
# Postmark sender

Sends one transactional email. Version 1.0.16.
