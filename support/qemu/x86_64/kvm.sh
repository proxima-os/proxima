#!/bin/sh
set -ue
# usage: kvm.sh image qemuflags

img="$1"
shift 1
echo Starting QEMU
qemu-system-x86_64 -accel kvm -cpu host -debugcon stdio -M q35,smm=off -cdrom "$img" "$@"
