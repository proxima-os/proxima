#!/bin/sh
set -e

if test "$#" -ne 1; then
    echo "usage: $0 OUTPUT" >&2
    exit 2
fi

# Clone, update, and build Limine
git clone https://github.com/limine-bootloader/limine.git --depth 1 --branch v8.x-binary
cd limine
git pull
make
cd ..

# Create ISO tree
dir=$(mktemp -d)
cleanup () {
    rm -rf "$dir"
}
trap cleanup EXIT

cmake --install . --prefix "$dir" --component runtime --strip

mkdir -p "$dir/EFI/BOOT"
cp limine/*.EFI "$dir/EFI/BOOT"
cp limine/limine-bios-cd.bin limine/limine-bios.sys limine/limine-uefi-cd.bin "$dir"
cat > "$dir/limine.conf" << EOF
timeout: 0

/Proxima
    protocol: limine
    kernel_path: boot():/boot/hydrogen
EOF

# Create ISO image
xorriso -as mkisofs -R -r -J -b limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$dir" -o "$1"
limine/limine bios-install "$1"
