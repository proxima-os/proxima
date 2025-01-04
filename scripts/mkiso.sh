#!/bin/sh
set -e
sdir=$(dirname "$0")

if test "$#" -ne 1; then
    echo "usage: $0 OUTPUT" >&2
    exit 2
fi

if ! test -d limine; then
    git clone https://github.com/limine-bootloader/limine.git --depth 1 --branch v8.x-binary
    cd limine
    make
    cd ..
fi

# Create ISO tree
dir=$(mktemp -d)
cleanup () {
    rm -rf "$dir"
}
trap cleanup EXIT

mkdir "$dir/boot"
"$sdir/geninitrd.sh" "$dir/boot/proxima.tar"
install -Dsm644 subprojects/hydrogen/kernel/hydrogen "$dir/boot/hydrogen"

mkdir -p "$dir/EFI/BOOT"
cp limine/*.EFI "$dir/EFI/BOOT"
cp limine/limine-bios-cd.bin limine/limine-bios.sys limine/limine-uefi-cd.bin "$dir"
cat > "$dir/limine.conf" << EOF
timeout: 0

/Proxima
    protocol: limine
    kernel_path: boot():/boot/hydrogen
    module_path: boot():/boot/proxima.tar
EOF

# Create ISO image
xorriso -as mkisofs -R -r -J -b limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$dir" -o "$1"
limine/limine bios-install "$1"
