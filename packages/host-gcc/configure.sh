# shellcheck shell=sh
"$src_extracted/configure" --target="$target" --prefix="$prefix_host" --with-sysroot="$sysroot" --disable-nls \
        --enable-languages=c,c++ --enable-initfini-array --enable-default-pie --without-headers --disable-shared
