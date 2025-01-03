# Proxima
A monolithic Unix-like operating system

## Build instructions
Make sure all submodules are up-to-date before beginning.

### Simple build
If you just want an ISO image, run the `build.sh` script. It takes the target architecture as an argument, and creates
an ISO image for you (at `build/proxima.iso`):
```sh
./build.sh x86_64
```

### Advanced build

Proxima is built just like any other Meson project. It is recommended to use the provided Clang-based toolchain files,
since that is what is used to develop the project. Currently, only x86_64 is supported:
`meson setup build --cross-file scripts/cross/x86_64.txt`

Note that some parts of Proxima rely on LTO inlining for performance. If you are making a release build, it is
recommended to enable LTO (add `-Db_lto=true -Db_lto_mode=thin` to your Meson setup command).

If you are installing Proxima to a hard drive, flash drive, or similar, just install it as any other Meson project
(with an appropriate `--destdir`, of course). This does not install a bootloader, you must set it up on your own.

If you want an ISO image, use the `mkiso.sh` script:
```sh
../scripts/mkiso.sh proxima.iso
```
Note that this script must be ran from within the Meson build directory. This downloads and sets up the bootloader for
you.
