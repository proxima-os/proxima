#!/bin/sh
set -e

if test "$#" -ne 1; then
    echo "usage: $0 ARCH" >&2
    exit 2
fi

mkdir build
cd build
cmake .. --toolchain "../cmake/cross/$1.cmake" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=1 \
    -G Ninja
ninja
../scripts/mkiso.sh proxima.iso
