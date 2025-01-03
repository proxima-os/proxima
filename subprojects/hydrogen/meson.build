project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    meson_version: '>=1.1.0',
    version: '0.1.0',
)

objcopy = find_program('objcopy')
strip = find_program('strip')

api_inc = include_directories('include')
priv_inc = include_directories('kernel/include', 'kernel/uacpi/include')

add_project_arguments(
    '-fno-common',
    '-DLIMINE_API_REVISION=2',
    '-DUACPI_OVERRIDE_LIBC',
    '-DUACPI_SIZED_FREES',
    language: 'c',
)

subdir('lib')
subdir('vdso')
subdir('kernel')
