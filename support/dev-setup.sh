#!/bin/sh
set -ue
# usage: dev-setup.sh [arch]

if test ! -f bootstrap.yml; then
    printf '%s: must be ran from within the source directory\n' "$0" >&2
    exit 2
fi

host="$(uname -m)"
dir="$(dirname "$(readlink -f -- "$0")")"

mkdir build
cd build

echo '*' > .gitignore
cat > bootstrap-site.yml << EOF
define_options:
  arch: '${1:-"$host"}'
  build-type: debug
  lto: 'false'
  host-gdb: enable
EOF

xbstrap init ..
"$dir/switch.sh" hydrogen

