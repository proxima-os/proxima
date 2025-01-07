# shellcheck shell=sh
make "-j$threads" inhibit_libc=true all-gcc all-target-libgcc
