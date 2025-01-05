linker_script = meson.current_source_dir() / 'vdso.lds'

vdso = shared_library(
    'hydrogen-vdso',
    'sched.c',
    'vfs.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    dependencies: proxutils,
    implicit_include_directories: false,
    include_directories: [api_inc, priv_inc],
    install: true,
    install_tag: 'devel',
    link_args: ['-nostdlib', '-T' + linker_script],
    link_depends: linker_script,
    sources: lib_sources,
)
