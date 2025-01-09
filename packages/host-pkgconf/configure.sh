# shellcheck shell=sh
"$src_extracted/configure" --prefix="$prefix_host" \
        --with-system-libdir="$sysroot$prefix/lib" \
        --with-system-includedir="$sysroot$prefix/include"
