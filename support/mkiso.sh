#!/bin/sh
set -ue
# usage: mkiso.sh sysroot output

isodir=$(mktemp -d)
cleanup () {
    rm -rf "$isodir"
}
trap cleanup EXIT

limine="$(limine --print-datadir)"
mkdir -p "$isodir/EFI/BOOT"
cp "$limine"/*.EFI "$isodir/EFI/BOOT"
cp "$limine"/limine-* "$isodir"
cat > "$isodir/limine.conf" << EOF
timeout: 0

/Proxima
    protocol: limine
    kernel_path: boot():/boot/hydrogen
    module_path: boot():/boot/proxima.tar
EOF

cp -r "$1/boot" "$isodir"
"$(dirname "$(readlink -f -- "$0")")/geninitrd.sh" "$1" "$isodir/boot/proxima.tar"

xorriso -as mkisofs -R -r -J -b limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$isodir" -o "$2"
limine bios-install "$2"
