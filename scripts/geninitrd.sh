#!/bin/sh
set -e

if test "$#" -ne 1; then
    echo "usage: $0 OUTPUT" >&2
    exit 2
fi

# Create file tree
dir=$(mktemp -d)
cleanup () {
    rm -rf "$dir"
}
trap cleanup EXIT
chmod 755 "$dir"
meson install --destdir "$dir" --tags runtime --strip
ln -s usr/lib "$dir/lib"

# Create archive
tar -H ustar -cf "$1" -C "$dir" --numeric-owner --owner=root --group=root --exclude='./boot' .
