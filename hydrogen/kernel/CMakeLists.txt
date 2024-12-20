add_executable(hydrogen
    src/cpu/cpu.c
    src/cpu/exc.c
    src/cpu/gdt.c
    src/cpu/gdt.S
    src/cpu/idt.c
    src/cpu/idt.S
    src/cpu/lapic.c
    src/cpu/lapic.S
    src/cpu/tss.c
    src/cpu/xsave.c
    src/drv/acpi.c
    src/drv/hpet.c
    src/drv/pic.c
    src/init/main.c
    src/init/main.S
    src/mem/heap.c
    src/mem/kvmm.c
    src/mem/pmap.c
    src/mem/pmm.c
    src/mem/vheap.c
    src/sched/mutex.c
    src/sched/proc.c
    src/sched/sched.c
    src/sched/sched.S
    src/sched/sema.c
    src/util/idmap.c
    src/util/list.c
    src/util/panic.c
    src/util/print.c
    src/util/string.c
    src/util/string.S
    src/util/time.c
    src/util/xarray.c
    ${UACPI_SOURCES}
)
target_compile_definitions(hydrogen PRIVATE LIMINE_API_REVISION=2 UACPI_OVERRIDE_LIBC)
target_compile_options(hydrogen PRIVATE -ffreestanding -fno-pie -fno-stack-check -fno-stack-protector -mcmodel=kernel
    -mgeneral-regs-only -mno-red-zone)
target_include_directories(hydrogen PRIVATE include ${UACPI_INCLUDES})
target_link_libraries(hydrogen PRIVATE hydrogen-api)
target_link_options(hydrogen PRIVATE -nostdlib -static)
target_link_script(hydrogen kernel.lds)

install(TARGETS hydrogen
    DESTINATION boot
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    COMPONENT runtime)
