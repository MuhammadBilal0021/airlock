"""airlock -- behavioural sandbox for agent skills and MCP servers.

Runs untrusted skill code against a synthetic machine seeded with canary-laced
credentials, inside a user/mount/network/PID namespace with no route to the
internet, then diffs what the skill *declared* against what it *did*.
"""

__version__ = "0.1.0"
