#!/bin/sh
set -ue
# usage: configure-host.sh src prefix arch triplet sysroot

case "$3" in
    x86_64)
        llvm_target=X86
        ;;
    *)  printf '%s: unknown architecture %s' "$0" "$3" >&2
        exit 2
        ;;
esac

cmake "$1/llvm" -GNinja                                  \
    -DCMAKE_INSTALL_PREFIX="$2"                          \
    -DCMAKE_BUILD_TYPE=Release                           \
    -DLLVM_LINK_LLVM_DYLIB=ON                            \
    -DLLVM_DEFAULT_TARGET_TRIPLE="$3-$4"                 \
    -DLLVM_TARGETS_TO_BUILD="$llvm_target"               \
    -DLLVM_ENABLE_PROJECTS='clang;clang-tools-extra;lld' \
    -DDEFAULT_SYSROOT="$5"
