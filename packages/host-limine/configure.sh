# shellcheck shell=sh
cfgargs=""

case "$target" in
x86_64-*) cfgargs="$cfgargs --enable-bios --enable-bios-cd --enable-uefi-x86-64 --enable-uefi-cd" ;;
esac

TOOLCHAIN_FOR_TARGET=gnu \
    AR_FOR_TARGET="$target-ar" \
    CC_FOR_TARGET="$target-gcc" \
    LD_FOR_TARGET="$target-ld" \
    OBJCOPY_FOR_TARGET="$target-objcopy" \
    OBJDUMP_FOR_TARGET="$target-objdump" \
    READELF_FOR_TARGET="$target-readelf" \
    "$src_extracted/configure" --prefix="$prefix_host" $cfgargs
