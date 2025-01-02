cmake_minimum_required(VERSION 3.28)
project(proxima VERSION 0.1.0 LANGUAGES C ASM)

include(cmake/utils.cmake)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(PROXIMA_ASSERTIONS "Enable assertions (always enabled in debug mode)")

add_compile_options(-fno-common -Wall -Wextra)
add_link_options(-nostdlib -Wl,-z,max-page-size=0x4000)

if (PROXIMA_ASSERTIONS)
    add_compile_definitions(PROXIMA_ASSERTIONS=1)
endif ()

add_subdirectory(hydrogen)
