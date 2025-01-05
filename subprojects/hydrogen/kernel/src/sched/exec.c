#include "sched/exec.h"
#include "asm/irq.h"
#include "cpu/xsave.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "proxima/compiler.h"
#include "proxima/elf.h"
#include "sched/proc.h"
#include "sched/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include "sys/vdso.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/spinlock.h"
#include <stdint.h>

#define DEFAULT_STACK_SIZE 0x2000

static uint8_t wanted_ident[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

static int read_fully(file_t *file, void *buffer, size_t size, uint64_t pos) {
    while (size > 0) {
        size_t cur = size;
        int error = vfs_pread(file, buffer, &size, pos, O_EXEC);
        if (unlikely(error)) return error;
        if (cur == 0) return ERR_INVALID_IMAGE;

        buffer += cur;
        size -= cur;
        pos += cur;
    }

    return 0;
}

static void memcpy_user_infallible(void *dest, const void *src, size_t count) {
    int error = memcpy_user(dest, src, count);
    if (unlikely(error)) panic("memcpy_user_infallible failed (%d)", error);
}

static void memset_user_infallible(void *dest, int value, size_t count) {
    int error = memset_user(dest, value, count);
    if (unlikely(error)) panic("memset_user_infallible failed (%d)", error);
}

static int load_elf(file_t *file, const elf_header_t *header, intptr_t *slide_out) {
    uintptr_t minv = UINTPTR_MAX;
    uintptr_t maxv = 0;

    for (int i = 0; i < header->phnum; i++) {
        uint64_t offset = header->phoff + (uint64_t)header->phentsize * i;
        elf_segment_t segment;
        int error = read_fully(file, &segment, sizeof(segment), offset);
        if (unlikely(error)) return error;

        if (segment.kind != PT_LOAD || segment.memsz == 0) continue;

        uintptr_t cminv = segment.vaddr;
        uintptr_t cmaxv = cminv + segment.memsz;
        if (cmaxv < cminv) return ERR_INVALID_IMAGE;

        if (cminv < minv) minv = cminv;
        if (cmaxv > maxv) maxv = cmaxv;
    }

    if (minv > maxv) {
        *slide_out = 0;
        return 0; // no loadable segments, doing nothing = loading it
    }

    uintptr_t addr = header->image_type == ET_DYN ? 0 : minv;
    int error = vmm_add(&addr, maxv - minv, header->image_type == ET_DYN ? 0 : VMM_EXACT, NULL, 0);
    if (unlikely(error)) return error;
    addr |= minv & PAGE_MASK;
    intptr_t slide = (intptr_t)addr - (intptr_t)minv;

    for (int i = 0; i < header->phnum; i++) {
        uint64_t offset = header->phoff + (uint64_t)header->phentsize * i;
        elf_segment_t segment;
        int error = read_fully(file, &segment, sizeof(segment), offset);
        if (unlikely(error)) {
            vmm_del(addr, maxv - minv);
            return error;
        }

        if (segment.kind != PT_LOAD || segment.memsz == 0) continue;

        int flags = VMM_EXACT | VMM_PRIVATE;
        if (segment.flags & PF_R) flags |= VMM_READ;
        if (segment.flags & PF_W) flags |= VMM_WRITE;
        if (segment.flags & PF_X) flags |= VMM_EXEC;
        if (flags == (VMM_EXACT | VMM_PRIVATE)) continue;

        uintptr_t vaddr = segment.vaddr + slide;
        uintptr_t file_end = vaddr;
        uintptr_t mem_end = vaddr + segment.memsz;

        if (segment.filesz) {
            file_end = (file_end + segment.filesz + PAGE_MASK) & ~PAGE_MASK;
            error = vfs_mmap(file, &vaddr, segment.filesz, flags, segment.offset, O_EXEC);
            if (unlikely(error)) {
                vmm_del(addr, maxv - minv);
                return error;
            }
        }

        if (file_end < mem_end) {
            error = vmm_add(&file_end, mem_end - file_end, flags, NULL, 0);
            if (unlikely(error)) {
                vmm_del(addr, maxv - minv);
                return error;
            }
        }

        if (segment.filesz != segment.memsz && (flags & VMM_WRITE) != 0) {
            memset_user_infallible((void *)(segment.vaddr + slide + segment.filesz), 0, segment.memsz - segment.filesz);
        }
    }

    *slide_out = slide;
    return 0;
}

static size_t add_to_info_block(const execve_string_t *str, size_t *pos, void *buffer, size_t size) {
    size_t idx = (*pos + 7) & ~7;
    size_t len = str->length + 8;
    size_t end = idx + len;

    if (end <= size) {
        memcpy_user_infallible(buffer + idx, &str->length, sizeof(str->length));
        memcpy_user_infallible(buffer + idx + 8, str->data, str->length);
    }

    *pos = end;
    return idx + 8;
}

static void add_auxv(void **start_info, UNUSED void *info_block, elf_auxv_t auxv) {
    memcpy_user_infallible(*start_info, &auxv, sizeof(auxv));
    *start_info += sizeof(auxv);
    ASSERT(*start_info <= info_block);
}

static int create_stack(
        uintptr_t *out,
        const elf_header_t *header,
        const elf_segment_t *phdr_seg,
        execve_string_t *argv,
        size_t narg,
        execve_string_t *envp,
        size_t nenv,
        intptr_t slide,
        intptr_t interpreter_slide
) {
    size_t info_block_size = 0;
    for (size_t i = 0; i < narg; i++) add_to_info_block(&argv[i], &info_block_size, NULL, 0);
    for (size_t i = 0; i < nenv; i++) add_to_info_block(&envp[i], &info_block_size, NULL, 0);

    size_t num_words_on_stack = narg + nenv + 7; // argc, the two null terminators, AT_SYSINFO_EHDR, AT_NULL
    if (phdr_seg) num_words_on_stack += 5 * 2;   // AT_BASE, AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM

    size_t start_info_size = (num_words_on_stack * 8 + info_block_size + 15) & ~15;
    size_t stack_size = (start_info_size + DEFAULT_STACK_SIZE + PAGE_MASK) & ~PAGE_MASK;

    // allocate area for stack incl. guard page
    uintptr_t stack_base;
    int error = vmm_add(&stack_base, stack_size + PAGE_SIZE, 0, NULL, 0);
    if (unlikely(error)) return error;
    stack_base += PAGE_SIZE;

    // allocate the stack itself
    error = vmm_add(&stack_base, stack_size, VMM_EXACT | VMM_WRITE, NULL, 0);
    if (unlikely(error)) {
        vmm_del(stack_base - PAGE_SIZE, stack_size + PAGE_SIZE);
        return error;
    }

    void *stack_top = (void *)(stack_base + stack_size - start_info_size);
    void *start_info = stack_top;
    void *info_block = stack_top + num_words_on_stack * 8;

    memcpy_user_infallible(start_info, &narg, sizeof(narg));
    start_info += sizeof(narg);
    ASSERT(start_info <= info_block);

    size_t ib_offset = 0;

    for (size_t i = 0; i < narg; i++) {
        size_t offset = add_to_info_block(&argv[i], &ib_offset, info_block, info_block_size);
        offset += (uintptr_t)info_block;
        memcpy_user_infallible(start_info, &offset, sizeof(offset));
        start_info += sizeof(offset);
        ASSERT(start_info <= info_block);
    }

    memset_user_infallible(start_info, 0, 8);
    start_info += 8;
    ASSERT(start_info <= info_block);

    for (size_t i = 0; i < nenv; i++) {
        size_t offset = add_to_info_block(&envp[i], &ib_offset, info_block, info_block_size);
        memcpy_user_infallible(start_info, &offset, sizeof(offset));
        start_info += sizeof(offset);
        ASSERT(start_info <= info_block);
    }

    ASSERT(ib_offset == info_block_size);

    memset_user_infallible(start_info, 0, 8);
    start_info += 8;
    ASSERT(start_info <= info_block);

    add_auxv(&start_info, info_block, (elf_auxv_t){AT_SYSINFO_EHDR, .a_val = current_proc->vdso});

    if (phdr_seg) {
        add_auxv(&start_info, info_block, (elf_auxv_t){AT_BASE, .a_val = interpreter_slide});
        add_auxv(&start_info, info_block, (elf_auxv_t){AT_ENTRY, .a_val = header->entry + slide});
        add_auxv(&start_info, info_block, (elf_auxv_t){AT_PHDR, .a_val = phdr_seg->vaddr + slide});
        add_auxv(&start_info, info_block, (elf_auxv_t){AT_PHENT, .a_val = header->phentsize});
        add_auxv(&start_info, info_block, (elf_auxv_t){AT_PHNUM, .a_val = header->phnum});
    }

    add_auxv(&start_info, info_block, (elf_auxv_t){AT_NULL});
    ASSERT(start_info == info_block);

    *out = (uintptr_t)stack_top;
    return 0;
}

void cleanup_execve_strings(execve_string_t *buf, size_t count) {
    for (size_t i = 0; i < count; i++) {
        vmfree(buf[i].data, buf[i].length);
    }

    vmfree(buf, sizeof(*buf) * count);
}

static _Noreturn void do_exec(
        file_t *file,
        const elf_header_t *header,
        const elf_segment_t *phdr_seg,
        execve_string_t *argv,
        size_t narg,
        execve_string_t *envp,
        size_t nenv,
        file_t *interpreter,
        const elf_header_t *iheader
) {
    // no locking necessary here, we're a singlethreaded process without usermode right now
    for (long i = 0; i < current_proc->fd_capacity; i++) {
        if (!current_proc->fds[i].file) continue;

        if (current_proc->fds[i].flags & FD_CLOEXEC) {
            file_deref(current_proc->fds[i].file);
            current_proc->fds[i].file = NULL;
        }
    }

    intptr_t image_slide;
    int error = load_elf(file, header, &image_slide);
    file_deref(file);
    if (unlikely(error)) {
        printk("exec: failed to load program image (%d)", error);
        cleanup_execve_strings(argv, narg);
        cleanup_execve_strings(envp, nenv);
        if (interpreter) file_deref(interpreter);
        sched_exit();
    }

    intptr_t interpreter_slide;
    if (interpreter) {
        error = load_elf(interpreter, iheader, &interpreter_slide);
        file_deref(interpreter);
        if (unlikely(error)) {
            printk("exec: failed to load interpreter image (%d)", error);
            cleanup_execve_strings(argv, narg);
            cleanup_execve_strings(envp, nenv);
            sched_exit();
        }
    }

    error = map_vdso(&current_proc->vdso);
    if (unlikely(error)) {
        printk("exec: failed to map vdso (%d)", error);
        cleanup_execve_strings(argv, narg);
        cleanup_execve_strings(envp, nenv);
        sched_exit();
    }

    uintptr_t stack;
    error = create_stack(&stack, header, phdr_seg, argv, narg, envp, nenv, image_slide, interpreter_slide);
    cleanup_execve_strings(argv, narg);
    cleanup_execve_strings(envp, nenv);
    if (unlikely(error)) {
        printk("exec: create_stack failed (%d)", error);
        sched_exit();
    }

    uintptr_t entry = interpreter ? iheader->entry + interpreter_slide : header->entry + image_slide;

    xreset();
    enter_user_mode(entry, stack);
}

// Does the final stuff that can have error recovery before switching to the newly created (empty) VMM
static int try_exec(
        file_t *file,
        const elf_header_t *header,
        const elf_segment_t *phdr_seg,
        execve_string_t *argv,
        size_t narg,
        execve_string_t *envp,
        size_t nenv,
        file_t *interpreter,
        const elf_header_t *iheader
) {
    irq_state_t state = spin_lock(&current_proc->lock);
    if (current_proc->tasks.first != current_proc->tasks.last) panic("TODO: exec in multithreaded process");
    spin_unlock(&current_proc->lock, state);

    // No more recovery after this!
    vmm_t *vmm;
    int error = vmm_create(&vmm);
    if (unlikely(error)) return error;
    vmm_switch(vmm);
    vmm_deref(current_proc->vmm);
    current_proc->vmm = vmm;

    do_exec(file, header, phdr_seg, argv, narg, envp, nenv, interpreter, iheader);
}

static int verify_header(const elf_header_t *header) {
    if (memcmp(header->ident, wanted_ident, sizeof(wanted_ident))) return ERR_INVALID_IMAGE;
    if (header->machine != EM_NATIVE) return ERR_INVALID_IMAGE;
    if (header->version != EV_CURRENT) return ERR_INVALID_IMAGE;
    return 0;
}

int execve(file_t *file, execve_string_t *argv, size_t narg, execve_string_t *envp, size_t nenv) {
    elf_header_t header;
    int error = read_fully(file, &header, sizeof(header), 0);
    if (unlikely(error)) return error;

    error = verify_header(&header);
    if (unlikely(error)) return error;
    if (header.image_type != ET_EXEC && header.image_type != ET_DYN) return ERR_INVALID_IMAGE;

    // try to find PT_INTERP and PT_PHDR
    file_t *interpreter = NULL;
    elf_segment_t phdr_seg;
    bool have_phdr = false;

    for (int i = 0; i < header.phnum; i++) {
        uint64_t offset = header.phoff + (uint64_t)header.phentsize * i;
        elf_segment_t segment;
        error = read_fully(file, &segment, sizeof(segment), offset);
        if (unlikely(error)) {
            if (interpreter) file_deref(interpreter);
            return error;
        }

        if (segment.kind == PT_INTERP) {
            if (interpreter != NULL) {
                file_deref(interpreter);
                return ERR_INVALID_IMAGE;
            }

            char *buf = vmalloc(segment.filesz);
            if (unlikely(!buf)) return ERR_OUT_OF_MEMORY;

            error = read_fully(file, buf, segment.filesz, segment.offset);
            if (unlikely(error)) {
                vmfree(buf, segment.filesz);
                return error;
            }

            error = vfs_open(NULL, &interpreter, buf, strnlen(buf, segment.filesz), O_EXEC | O_NODIR, 0);
            vmfree(buf, segment.filesz);
            if (unlikely(error)) return error;
        } else if (segment.kind == PT_PHDR) {
            if (have_phdr) {
                if (interpreter != NULL) file_deref(interpreter);
                return ERR_INVALID_IMAGE;
            }

            phdr_seg = segment;
            have_phdr = true;
        }
    }

    elf_header_t iheader;

    if (interpreter != NULL) {
        if (!have_phdr) {
            file_deref(interpreter);
            return ERR_INVALID_IMAGE;
        }

        int error = read_fully(interpreter, &iheader, sizeof(iheader), 0);
        if (unlikely(error)) {
            file_deref(interpreter);
            return error;
        }

        error = verify_header(&iheader);
        if (unlikely(error)) {
            file_deref(interpreter);
            return error;
        }

        if (iheader.image_type != ET_DYN) {
            file_deref(interpreter);
            return ERR_INVALID_IMAGE;
        }
    }

    error = try_exec(
            file,
            &header,
            (have_phdr && interpreter) ? &phdr_seg : NULL,
            argv,
            narg,
            envp,
            nenv,
            interpreter,
            interpreter ? &iheader : NULL
    );
    if (interpreter) file_deref(interpreter);
    return error;
}
