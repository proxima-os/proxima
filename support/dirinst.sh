#!/bin/sh
set -ue
# usage: dirinst.sh output

if test ! -L bootstrap.link; then
    printf '%s: must be ran from within the build directory\n' "$0" >&2
    exit 2
fi

sysroot=system-root

limine="$(xbstrap runtool host-limine -- limine --print-datadir)"
mkdir -p "$1/EFI/BOOT"
cp "$limine"/*.EFI "$1/EFI/BOOT"
cat > "$1/limine.conf" << EOF
timeout: 0

/Proxima
    protocol: limine
    kernel_path: boot():/boot/hydrogen
    module_path: boot():/boot/proxima.tar
EOF

cp -r "$sysroot/boot" "$1"
"$(dirname "$(readlink -f -- "$0")")/geninitrd.sh" "$sysroot" "$1/boot/proxima.tar"
