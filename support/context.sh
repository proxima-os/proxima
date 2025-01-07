#!/bin/sh
set -e

if test "$#" -ne 1; then
    echo "usage: $0 SCRIPT"
    exit 2
fi

sysroot="$broot/sysroot"
prefix=/usr
prefix_host="$broot/tools"

export PATH="$prefix_host/bin:$PATH"

meson_configure() {
    src="$1"
    shift 1

    meson setup "$src" . --cross-file="$meson_cross" -Dbuildtype=release -Db_lto=true -Db_lto_mode=thin \
            -Db_ndebug=true -Dprefix="$prefix" "$@"
}

meson_install() {
    meson install --destdir "$sysroot"
}

. "$1"
