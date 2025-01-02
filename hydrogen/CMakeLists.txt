include(uacpi/uacpi.cmake)

add_library(hydrogen-api INTERFACE)
target_include_directories(hydrogen-api INTERFACE include)

add_subdirectory(kernel)
add_subdirectory(vdso)
