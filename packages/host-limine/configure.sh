# shellcheck shell=sh

do_configure() {
    TOOLCHAIN_FOR_TARGET=gnu \
        AR_FOR_TARGET="$TARGET-gcc-ar" \
        CC_FOR_TARGET="$TARGET-gcc" \
        LD_FOR_TARGET="$TARGET-ld" \
        OBJCOPY_FOR_TARGET="$TARGET-objcopy" \
        OBJDUMP_FOR_TARGET="$TARGET-objdump" \
        READELF_FOR_TARGET="$TARGET-readelf" \
        "$SRC_EXTRACTED/configure" --prefix="$PREFIX_HOST" "$@"
}

case "$TARGET" in
x86_64-*)   do_configure --enable-bios --enable-bios-cd --enable-uefi-x86-64 --enable-uefi-cd ;;
*)          echo "unhandled target $TARGET" >&2
            exit 2
            ;;
esac
