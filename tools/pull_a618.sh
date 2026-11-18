#!/bin/bash
set -e
cd /mnt/g/_Projects/sweet_ios
echo "=== adb devices ==="
adb devices 2>&1 | tail -2
echo "=== pulling console ring ==="
bash tools/sweet-log-pull.sh -s 558c58c4 /tmp/sweetlog-a618.bin 2>&1 | tail -5
echo "=== raw sweetlog adreno lines ==="
grep -a "sweetlog adreno" /tmp/sweetlog-a618.bin 2>/dev/null | head -80
echo "=== tail context around panic (last sweetlog + panic) ==="
grep -a -n -E "sweetlog|panic|data abort|Kernel" /tmp/sweetlog-a618.bin 2>/dev/null | tail -40
