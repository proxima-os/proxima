project(
    'proxima-devicesd',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    meson_version: '>=1.4.0',
    version: '0.1.0',
)

hydrogen = dependency('hydrogen')
uacpi = subproject('uacpi')

inc = []
src = []

inc += uacpi.get_variable('includes')
src += uacpi.get_variable('sources')

subdir('arch' / host_machine.cpu_family())

executable(
    'proxima-devicesd',
    'acpi/acpi.c',
    'acpi/kernel-api.c',
    'acpi/serial.c',
    'pci/pci.c',
    'main.c',
    c_args: ['-DUACPI_FORMATTED_LOGGING', '-DUACPI_NATIVE_ALLOC_ZEROED', '-DUACPI_SIZED_FREES'],
    dependencies: hydrogen,
    include_directories: inc,
    install: true,
    sources: src,
)
