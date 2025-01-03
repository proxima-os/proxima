#!/bin/sh
set -e

if test "$#" -ne 1; then
    echo "usage: $0 ARCH" >&2
    exit 2
fi

meson setup build --reconfigure --cross-file="scripts/cross/$1.txt" -Dbuildtype=release -Db_lto=true -Db_lto_mode=thin \
    -Db_ndebug=true
cd build
../scripts/mkiso.sh proxima.iso
