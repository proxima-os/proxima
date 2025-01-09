# shellcheck shell=sh

mkdir -p "$sysroot"
ln -s usr/bin "$sysroot/bin"
ln -s usr/lib "$sysroot/lib"
