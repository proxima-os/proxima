#!/bin/sh
set -ue
# usage: clangd.sh builddir args...

cd "$1"
if test ! -L bootstrap.link; then
    printf '%s: %s is not a valid build directory\n' "$0" "$1" >&2
    exit 2
fi
shift 1

pkg="$(readlink compile_commands.json)"
pkg="${pkg%/*}"
pkg="${pkg##*/}"

exec xbstrap lsp "$pkg" -- \
        env 'HOME=@BUILD_ROOT@/clangd' 'XDG_CACHE_HOME=@BUILD_ROOT@/clangd/cache' \
        clangd --background-index '--compile-commands-dir=@BUILD_ROOT@' \
                --path-mappings '@HOST_BUILD_ROOT@=@BUILD_ROOT@,@HOST_SOURCE_ROOT@=@SOURCE_ROOT@' \
                "$@"
