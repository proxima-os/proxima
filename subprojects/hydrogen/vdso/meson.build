linker_script = meson.current_source_dir() / 'vdso.lds'

vdso = shared_library(
    'hydrogen-vdso',
    'main.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    implicit_include_directories: false,
    include_directories: [api_inc, priv_inc],
    install: true,
    link_args: ['-nostdlib', '-T' + linker_script],
    link_depends: linker_script,
    sources: lib_sources,
)
