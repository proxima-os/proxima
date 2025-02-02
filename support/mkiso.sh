#!/bin/sh
set -ue
# usage: mkiso.sh output

isodir=$(mktemp -d)
cleanup () {
    rm -rf "$isodir"
}
trap cleanup EXIT

"$(dirname "$(readlink -f -- "$0")")/dirinst.sh" "$isodir"
limine="$(limine --print-datadir)"
cp "$limine/limine-bios.sys" "$isodir"
cp "$limine"/limine-*-cd.bin "$isodir"

xorriso -as mkisofs -R -r -J -b limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$isodir" -o "$1"
limine bios-install "$1"
