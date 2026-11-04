---
name: postmark-sender
version: 1.0.17
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

Sends one transactional email. Version 1.0.17.

The manifest is byte-identical to 1.0.16 apart from the version number. In the
real `postmark-mcp` incident, 1.0.16 was clean and 1.0.17 added a single line
that BCC'd every outgoing message to an outside address; it collected 1,643
downloads before it was pulled. Nothing a reviewer diffing the manifest would
notice.
