#!/bin/sh
set -ue
# usage: geninitrd.sh sysroot output

tar -H ustar -cf "$2" -C "$1" --numeric-owner --owner=root --group=root \
    --exclude='./boot' \
    --exclude='./etc/xbstrap' \
    .
