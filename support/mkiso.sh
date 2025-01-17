#!/bin/sh
set -ue

isodir=$(mktemp -d)
tardir=$(mktemp -d)
cleanup () {
    rm -rf "$isodir" "$tardir"
}
trap cleanup EXIT

# Create ISO tree
cp -r "$1/boot" "$isodir"
chmod 755 "$tardir"
cp -RT "$1" "$tardir"
tar -H ustar -cf "$isodir/boot/proxima.tar" -C "$tardir" --numeric-owner --owner=root --group=root --exclude='./boot' .

mkdir -p "$isodir/EFI/BOOT"
cp "$2/share/limine"/*.EFI "$isodir/EFI/BOOT"
cp "$2/share/limine"/limine-* "$isodir"
cat > "$isodir/limine.conf" << EOF
timeout: 0

/Proxima
    protocol: limine
    kernel_path: boot():/boot/hydrogen
    module_path: boot():/boot/proxima.tar
EOF

# Create ISO image
xorriso -as mkisofs -R -r -J -b limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$isodir" -o "$3"
"$2/bin/limine" bios-install "$3"
