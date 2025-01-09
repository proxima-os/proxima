# shellcheck shell=sh
meson_configure "$pkgdir/src" -Db_lto=true -Db_lto_mode=thin -Db_ndebug=true
