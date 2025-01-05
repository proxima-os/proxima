project(
    'ld',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    version: '0.1.0',
)

hydrogen = dependency('hydrogen')

shared_library(
    'ld64',
    'entry.S',
    'link.c',
    'main.c',
    'string.c',
    c_args: ['-ffreestanding', '-fno-stack-protector'],
    dependencies: hydrogen,
    install: true,
    link_args: ['-nostdlib'],
    name_prefix: '',
    soversion: 1,
)
