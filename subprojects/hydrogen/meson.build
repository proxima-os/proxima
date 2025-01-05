project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    meson_version: '>=1.1.0',
    version: '0.1.0',
)

proxutils = dependency('proxutils')

objcopy = find_program('objcopy')
strip = find_program('strip')

api_inc = include_directories('include')
priv_inc = include_directories('kernel/include')

add_project_arguments(
    '-fno-common',
    '-DLIMINE_API_REVISION=2',
    '-DUACPI_OVERRIDE_LIBC',
    '-DUACPI_SIZED_FREES',
    language: 'c',
)

uacpi = subproject('uacpi')

subdir('lib')
subdir('vdso')
subdir('kernel')

install_headers(
    'include/hydrogen/dirent.h',
    'include/hydrogen/error.h',
    'include/hydrogen/fcntl.h',
    'include/hydrogen/limits.h',
    'include/hydrogen/sched.h',
    'include/hydrogen/stat.h',
    'include/hydrogen/vfs.h',
    subdir: 'hydrogen',
)

hydrogen_dep = declare_dependency(include_directories: api_inc, dependencies: proxutils, link_with: vdso)
meson.override_dependency('hydrogen', hydrogen_dep)
