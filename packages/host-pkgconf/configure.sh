# shellcheck shell=sh
"$SRC_EXTRACTED/configure" --prefix="$PREFIX_HOST" \
        --with-system-libdir="$SYSROOT$PREFIX/lib" \
        --with-system-includedir="$SYSROOT$PREFIX/include"
