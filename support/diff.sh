#!/bin/sh
set -ue
# usage: diff.sh package base-revision

if test ! -f bootstrap.yml; then
    printf '%s: must be ran from within the source directory\n' "$0" >&2
    exit 2
fi

cd "ports/$1"
git format-patch -No "../../patches/$1" --always "$2"
