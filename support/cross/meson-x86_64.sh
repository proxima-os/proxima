#!/bin/sh
set -ue
# usage: meson-x86_64.sh output sysroot

cat > "$1" << EOF
[binaries]
ar = 'x86_64-unknown-proxima-gcc-ar'
c = 'x86_64-unknown-proxima-gcc'
cpp = 'x86_64-unknown-proxima-g++'
nm = 'x86_64-unknown-proxima-gcc-nm'
objcopy = 'x86_64-unknown-proxima-objcopy'
pkg-config = 'pkgconf'
ranlib = 'x86_64-unknown-proxima-gcc-ranlib'
strip = 'x86_64-unknown-proxima-strip'

[host_machine]
system = 'proxima'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[built-in options]
c_args = ['-fdata-sections', '-ffunction-sections']
c_link_args = ['-Wl,--gc-sections,--sort-section=alignment']
cpp_args = c_args
cpp_link_args = c_link_args
libdir = 'lib'

[properties]
sys_root = '$2'
pkg_config_libdir = '$2/usr/lib/pkgconfig'
EOF
