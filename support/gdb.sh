#!/bin/sh
set -ue
# usage: gdb.sh gdbflags
# assumes the build directory is at <script dir>/../build

dir="$(dirname "$(readlink -f -- "$0")")/../build"

exec xbstrap -C "$dir" runtool gdb -- '@OPTION:arch@-@OPTION:triplet@-gdb' "$@"
