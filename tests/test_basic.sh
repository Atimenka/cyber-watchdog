#!/bin/bash
set -e
cmake -B /tmp/cw-test -S "$(dirname $0)/.." 2>/dev/null
cmake --build /tmp/cw-test -j$(nproc) 2>/dev/null
/tmp/cw-test/cyber-watchdog --help
/tmp/cw-test/cyber-watchdog -r
echo "PASS"
rm -rf /tmp/cw-test
