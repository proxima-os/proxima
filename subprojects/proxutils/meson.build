project(
    'proxutils',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    version: '0.1.0',
)

inc = include_directories('include')

install_headers('include/proxima/compiler.h', 'include/proxima/elf.h', subdir: 'proxima')

proxutils_dep = declare_dependency(include_directories: inc)
meson.override_dependency('proxutils', proxutils_dep)
