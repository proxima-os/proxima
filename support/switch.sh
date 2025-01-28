#!/bin/sh
set -ue
# usage: switch.sh package

if test ! -L bootstrap.link; then
    printf '%s: must be ran from within the build directory\n' "$0" >&2
    exit 2
fi

xbstrap configure "$1"
exec xbstrap lsp "$1" -- \
        ln -srf '@THIS_BUILD_DIR@/compile_commands.json' '@BUILD_ROOT@/compile_commands.json'
