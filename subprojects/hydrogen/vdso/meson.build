linker_script = files('vdso.lds')[0]

vdso = shared_library(
    'hydrogen-vdso',
    'main.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    implicit_include_directories: false,
    include_directories: [api_inc, priv_inc],
    link_args: ['-nostdlib', '-T' + linker_script.full_path()],
    link_depends: linker_script,
    sources: lib_sources,
)
