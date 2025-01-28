#!/bin/sh
set -ue
# usage: tcg.sh image qemuflags

img="$1"
shift 1
echo Starting QEMU
qemu-system-x86_64 -cpu max -M q35,smm=off -cdrom "$img" "$@"
