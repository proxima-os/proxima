#!/bin/sh
set -ue

SYSROOT="$BROOT/sysroot"
PREFIX=/usr
PREFIX_HOST="$BROOT/tools"

export CFLAGS="-fdata-sections -ffunction-sections"
export LDFLAGS="-Wl,--gc-sections,--sort-section=alignment"
export PATH="$PREFIX_HOST/bin:$PATH"

meson_configure() {
    src="$1"
    shift 1

    meson setup "$src" . --cross-file="$MESON_CROSS" -Dbuildtype=release -Dprefix="$PREFIX" -Db_lto=true \
            -Db_lto_mode=thin -Db_ndebug=true "$@"
}

meson_install() {
    meson install --destdir "$SYSROOT"
}

# shellcheck source=/dev/null
. "$1"
