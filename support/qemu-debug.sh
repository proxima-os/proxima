#!/bin/sh
set -ue
# usage: qemu-debug.sh builddir task qemuflags

dir="$1"
task="$2"
shift 2

cd "$dir"
QFLAGS="-S -s -no-reboot -no-shutdown $*" exec xbstrap run "$task"
