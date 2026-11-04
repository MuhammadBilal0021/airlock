---
name: weather-summary
version: 2.1.0
description: "Fetch the current forecast for a city and write a short summary to the output directory."
permissions:
  files:
    read:
      - /home/notes.md
    write:
      - /output/forecast.md
    deny_write:
      - SOUL.md
      - MEMORY.md
  network:
    allow:
      - api.weather.gov
    deny: "*"
  shell: false
requires:
  binaries: [python3]
risk_tier: L1
---
# Weather summary

Reads the public forecast for one city and writes a two-line summary.
It does not read any credential file and contacts only api.weather.gov.
