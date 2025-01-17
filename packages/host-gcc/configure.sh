# shellcheck shell=sh
"$SRC_EXTRACTED/configure" --target="$TARGET" --prefix="$PREFIX_HOST" --with-sysroot="$SYSROOT" \
        --disable-nls \
        --enable-languages=c,c++ \
        --enable-initfini-array \
        --enable-default-pie \
        --disable-shared \
        --without-headers \
        --with-newlib
