#!/bin/sh
set -ue
# usage: tcg.sh image qemuflags

img="$1"
shift 1
echo Starting QEMU
qemu-system-x86_64 -cpu max,-la57 -M q35,smm=off -debugcon stdio -cdrom "$img" "$@"
