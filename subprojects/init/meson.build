project(
    'init',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    version: '0.1.0',
)

hydrogen = dependency('hydrogen')

executable(
    'init',
    'main.c',
    c_args: ['-ffreestanding', '-fno-stack-protector'],
    dependencies: hydrogen,
    install: true,
    link_args: ['-nostdlib'],
)
