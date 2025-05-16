#!/bin/sh
set -ue
# usage: meson-x86_64.sh output sysroot triplet

cat > "$1" << EOF
[binaries]
ar = '$3-gcc-ar'
c = '$3-gcc'
cpp = '$3-g++'
nm = '$3-gcc-nm'
objcopy = '$3-objcopy'
pkg-config = 'pkgconf'
ranlib = '$3-gcc-ranlib'
strip = '$3-strip'

[host_machine]
system = 'hydrogen'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[built-in options]
c_args = ['-fdata-sections', '-ffunction-sections', '--sysroot=$2']
c_link_args = ['-Wl,--gc-sections,--sort-section=alignment']
cpp_args = c_args
cpp_link_args = c_link_args
libdir = 'lib'

[properties]
sys_root = '$2'
pkg_config_libdir = '$2/usr/lib/pkgconfig'
EOF
