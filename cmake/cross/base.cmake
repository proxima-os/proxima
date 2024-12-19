set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld -Wl,--gc-sections,--sort-section=alignment")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS_INIT}")

foreach(lang ASM C CXX)
    set(CMAKE_${lang}_COMPILER clang)
    set(CMAKE_${lang}_COMPILER_TARGET "${CMAKE_SYSTEM_PROCESSOR}-unknown-linux-gnu")
    set(CMAKE_${lang}_FLAGS_INIT "-fdata-sections -ffunction-sections -nostdlibinc")
endforeach()

set(CMAKE_CXX_COMPILER clang++)
