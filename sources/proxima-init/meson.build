project(
    'proxima-init',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    meson_version: '>=1.4.0',
    version: '0.1.0',
)

hydrogen = dependency('hydrogen')

executable('init', 'main.c', dependencies: hydrogen, install: true)
