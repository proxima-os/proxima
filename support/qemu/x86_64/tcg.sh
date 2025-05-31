#!/bin/sh
set -ue
# usage: tcg.sh image qemuflags

img="$1"
shift 1
echo Starting QEMU
qemu-system-x86_64 -cpu max,-la57 -m 4G -M q35 -debugcon stdio -cdrom "$img" "$@"
