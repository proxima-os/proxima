#!/bin/sh
set -e

if test "$#" -ne 2; then
    echo "usage: $0 IMAGE SIZE" >&2
    exit 2
fi

dd of="$1" bs=1 count=0 seek="$2" status=none # Set image size
dd if=/dev/zero of="$1" bs=1024 count=1 seek=1 conv=notrunc status=none # Erase superblock
mke2fs "$1" # Create filesystem

mnt=""
cleanup () {
    set +e

    if test "x$mnt" != x; then
        fusermount3 -u "$mnt"
        rmdir "$mnt"
    fi
}
trap cleanup EXIT

mnt=$(mktemp -d)
fuse2fs "$1" "$mnt" -o fakeroot,rw

cmake --install . --prefix "$mnt" --component runtime --strip
chown -R 0:0 "$mnt"
