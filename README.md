# Proxima
A monolithic Unix-like operating system

## Dependencies

Proxima's build system requires the following packages to be present on the host system:
- bash
- bison
- flex
- gcc/clang
- g++/clang++
- git
- gmp (development package)
- isl (development package)
- m4
- make
- meson
- mtools
- nasm
- ninja
- mpc (development package)
- mpfr (development package)
- perl
- tar (GNU version)
- [xbstrap](https://github.com/managarm/xbstrap)
- xorriso

## Building

Make sure all submodules are up-to-date before beginning.

Create a build directory somewhere, and initialize it:
```sh
mkdir build && cd build
cat > bootstrap-site.yml << EOF
define_options:
  arch: $(uname -m) # change this if you want to compile for a different architecture
EOF
xbstrap init <source dir>
```

### ISO image

If you want to include extra packages beyond the default, run:
```sh
xbstrap install <packages>
```

Create the ISO image:
```sh
xbstrap run make-iso
```
This command writes the ISO to `proxima.iso`.

### Something else

If you do not want to create an ISO image (e.g. if you want to create a custom image or install Proxima to a mounted
partition), you must create a system root and manually copy it to your desired location:
```sh
xbstrap install proxima <extra packages>
cp -pR system-root/. <destination>
```

Note that the installed files will be owned by the user that built the system.

## Running

Proxima includes xbstrap tasks that run the built ISO image.
```sh
xbstrap run qemu-kvm # use this if kvm is available and you do not need qemu's debugging features
xbstrap run qemu-tcg # otherwise, use this
```
If you want to pass extra arguments to QEMU, pass them in the `QFLAGS` environment variable.

## Contributing

To set up a development environment, run:
```sh
support/dev-setup.sh [arch]
```
If `arch` is not specified, the current host architecture is used.

This sets up a build directory at `build` where all **first-party** packages are built in debug mode instead of
release mode. The name of the directory cannot be changed because some development scripts rely on it. The tools
necessary for development are built immediately by the script.

Several scripts have the notion of an 'active package'. For example, `support/rebuild.sh` rebuilds the active package,
and `support/clangd.sh` starts clangd for the active package. `support/dev-setup.sh` sets this to `hydrogen`.
To change the active package, run this from the build directory:
```sh
../support/switch.sh <package>
```

Configuration files for Visual Studio Code are included in the repository. If you use a different editor, you can use
them as reference. Of particular note is `.vscode/settings.json`, which shows how to set up the clangd language server.

### Adding a new package

Each package has a manifest file at `packages/<name>.yml`, which describes how to obtain its sources
and how to build it. When creating a new package, you must also add this file to the `imports` list in `bootstrap.yml`.

The target triplet for Proxima is `@OPTION:arch@-unknown-proxima`.

#### First-party

First-party package manifests must follow the following rules (non-exhaustive):
- The source subdirectory must be `sources`.
- The source version must be `0.0pl@ROLLING_ID@`.
- The configuration command must respect `@OPTION:build-type@` and ensure `compile_commands.json` gets generated.

It is recommended to use an existing first-party manifest (such as `packages/hydrogen.yml`) as a reference when creating
a new one.

#### Third-party (including tools)

Third-party package manifests must follow the following rules (non-exhaustive):
- The source subdirectory must be `ports`.
- Sources must be downloaded as a tarball unless they need to be patched.
  - Tarball checksums must use blake2b.
  - Git sources must be cloned from the original repository; using a mirror is not allowed.
  - Git sources must be pinned to a specific tag or commit.
- The configuration command must **ignore** `@OPTION:build-type@` and `@OPTION:lto@`.
- Tools must use separately defined sources (i.e. use `from_source` instead of `source`) to facilitate future porting.
- Patches must be as minimal as possible. If a patch is only necessary due to a bug or missing feature in a dependency,
  fix the bug or implement the missing feature instead of patching the package. For example, `autoconf`-based packages
  usually need to have their build systems regenerated: use `support/autoconf/regenerate.sh` for this, even if the
  package needs to be patched for other reasons as well.
- When making changes to a package's sources, address the root cause of the issue if possible instead of adding hacks.
  For example, some `autoconf`-based packages have outdated `configure.ac`/`configure.in` files that fail when used
  with newer versions of `autoconf`. The preferred solution here is to exclude the offending directory from regeneration
  (the issue is usually in outdated in-repo dependencies, not in the package itself). If that is not possible or limits
  the package's features, try to fix the offending file before changing the generated files.

It is recommended to use an existing third-party manifest (such as `packages/libtool.yml`) as a reference when creating
a new one.

#### Tips

- Installing the `host-meson` tool generates a Meson toolchain file at `@BUILD_ROOT@/tools/host-meson/cross.txt`.
