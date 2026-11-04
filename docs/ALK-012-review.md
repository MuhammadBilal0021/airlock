# ALK-012: owner review draft

This rule was drafted with AI assistance for Muhammad Bilal's review. It is not
represented as independently hand-written work. T3 remains pending until the
owner can explain, challenge and extend the implementation.

## Concrete behaviour

The fixture changes the synthetic SSH private key from `0600` to `0644`, without
opening its contents or contacting a host. Before this change, a chmod-only
operation was invisible because size and mtime do not change. The snapshot now
also records Unix mode bits using stat, without reading file contents.

The filesystem diff emits a separate `permissions` event even if content also
changes. The engine applies ALK-012 only to planted credential paths when:

```python
added_access = mode_after & ~mode_before & 0o066
```

`0060` selects group read/write, and `0006` selects other-user read/write.
The complement of the old mode removes permissions that were already present.
Thus `0600 -> 0644` fires; `0644 -> 0600`, unchanged modes, owner-only changes,
execute-only changes and non-credential files do not.

The finding is **medium, confirmed, AST03**. Confirmed means the mode transition
is observed. It does not mean anyone used those permissions, that a containing
directory permits traversal, or that data left the sandbox. Medium contributes
8 points; the aggregate label is therefore LOW unless other findings add risk.

## Limits to explain

- This observes the final snapshot, so a chmod restored before exit is missed.
- It does not evaluate POSIX ACLs, group membership or parent-directory modes.
- Newly created credential copies are handled by canary staging detection;
  this rule compares pre-existing planted credentials only.
- Declaring a write does not suppress the finding: permission broadening is
  useful evidence even for an authorized write. The declaration is displayed.
- No runtime dependency, syscall trace or new process-sampling claim is added.

## Review exercise

1. Explain why chmod can evade a size/mtime diff and why stat preserves atime.
2. Calculate the mask for `0600 -> 0620` and `0644 -> 0600` by hand.
3. Decide whether medium is justified, given the limits above.
4. Run the fixture and inspect the before/after evidence in JSON and SARIF.
5. Add a case you think is missing, such as a content write and chmod in the
   same run, and explain what observation would change your conclusion.

```sh
python3 -m unittest discover -s tests -v
python3 -m airlock scan fixtures/08-credential-permissions --format json --fail-on none
python3 -m airlock scan fixtures/08-credential-permissions --format sarif --fail-on none
```

The automated tests cover read and write broadening, narrowing, unchanged and
owner/execute-only modes, non-credential files, the real chmod-only fixture,
absence of invented secret-read/exfiltration findings, and quiet controls 01/06.
