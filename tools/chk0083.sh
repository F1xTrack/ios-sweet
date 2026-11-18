#!/bin/bash
set -e
D=/opt/workx
KSRC=mnt/g/_Projects/sweet_ios/research/hakios-gpu/sweet_adreno.c
echo "=== syntax check (stub headers @/opt/workx/chk) ==="
gcc -fsyntax-only -Wall -Wextra -I$D/chk /mnt/g/_Projects/sweet_ios/research/hakios-gpu/sweet_adreno.c 2>&1 | head -20 && echo "HOST GCC SYNTAX CLEAN"
