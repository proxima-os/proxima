# shellcheck shell=sh

mkdir -p "$SYSROOT"
mkdir -p "$SYSROOT/usr/bin"
mkdir -p "$SYSROOT/usr/include"
mkdir -p "$SYSROOT/usr/lib"

ln -s usr/bin "$SYSROOT/bin"
ln -s usr/lib "$SYSROOT/lib"
