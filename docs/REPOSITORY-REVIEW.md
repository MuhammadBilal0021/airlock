# Public repository review — 6 November 2026

Reviewed GitHub main at `2108e01d68b5413d959aacdecfd6ed0df36e7770` through
the GitHub connector, including its complete recursive tree. Its 55 file paths
were checked locally at that exact Git object for common credential signatures.
This is a targeted current-tree review, not a full-history secret audit or
independent security certification. No remote files were changed.

## Publication recommendations

1. **Move PROJECT_BRIEF.md out of public product documentation.** It mixes
   personal portfolio advice, interview scripts, market positioning and launch
   tactics with technical planning. Keep a private copy and publish only a
   concise technical roadmap. Removing the current file would not remove it
   from Git history; nothing here warrants automatic history rewriting.
2. **Qualify security claims.** SECURITY.md says only the decoy home and skill
   are mounted, but runtime directories are also bound from the host. README's
   absolute host-safety statements exceed the published containment evidence.
   Describe the actual threat model, permitted runtime access, tested controls
   and remaining limitations. The local hardening is not yet on public main.
3. **Verify the reporting channel.** SECURITY.md lists an email address with an
   explicit fallback if it is not live. Publish a confirmed, monitored channel
   and realistic response targets. This review did not test that mailbox or
   repository private-reporting settings.
4. **Tighten comparative claims.** Broad statements that competing scanners do
   not work should become specific, attributed results with versions, dates,
   configurations and limitations. Airlock's own heuristic failures make an
   absolute superiority claim inappropriate. This review did not independently
   reproduce the cited third-party comparisons.
5. **Keep local diagnostics out of commits.** PROBE.txt and the root-level
   airlock-run probe/process files are untracked locally, not present on public
   main. The existing directory-only ignore rule does not cover those files.
   Review research captures for paths, contents and upstream licenses before
   publishing a curated dataset; do not blindly add the entire research tree.
6. **Harden action inputs before recommending broad CI adoption.** The public
   action interpolates input expressions directly into Bash. Pass inputs through
   environment variables and quote their expansions so caller-provided values
   remain data. This is separate from the runner repair and was not changed here.

## What should stay

The license, contribution guide, security policy (after correction), tests,
synthetic malicious fixtures and reproducible demo reports belong in a security
tool repository. Fixture behavior should continue to be exercised only inside
the sandbox. Fake key headers in `airlock/decoys.py` are deliberate templates,
not discovered live keys. No obvious GitHub/OpenAI tokens or AWS access IDs were
found by the targeted signature scan. VERIFICATION.md contains a local workspace
path; it is low-sensitivity provenance and can be generalized for portability.

## Overall assessment

Good research-prototype structure: a small dependency-free core, explicit rule
IDs, tests, examples, licensing and reproducible evidence. Public wording is
more confident than its validation, and the large unpublished working tree
means the README and public implementation lag local progress. Prioritize
correctness and reviewable commits before promotion. The newly observed
duplicate-main runner defect, MCP interface and expanded CI checks were local,
not present on the reviewed public main.

Sources: [public tree](https://github.com/MuhammadBilal0021/airlock/tree/2108e01d68b5413d959aacdecfd6ed0df36e7770),
[project brief](https://github.com/MuhammadBilal0021/airlock/blob/2108e01d68b5413d959aacdecfd6ed0df36e7770/PROJECT_BRIEF.md),
[security policy](https://github.com/MuhammadBilal0021/airlock/blob/2108e01d68b5413d959aacdecfd6ed0df36e7770/SECURITY.md),
[README](https://github.com/MuhammadBilal0021/airlock/blob/2108e01d68b5413d959aacdecfd6ed0df36e7770/README.md).
