#include "sys/elf.h"
#include "hydrogen/error.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "string.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

static const uint8_t wanted_ident[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

int load_elf_image(const elf_header_t *image, vm_object_t *object, uintptr_t extra, load_addr_info_t *out) {
    if (memcmp(image->ident, wanted_ident, sizeof(wanted_ident)) != 0) return ERR_INVALID_IMAGE;
    if (image->image_type != ET_DYN) return ERR_INVALID_IMAGE;
    if (image->machine != EM_NATIVE) return ERR_INVALID_IMAGE;
    if (image->version != EV_CURRENT) return ERR_INVALID_IMAGE;

    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;

    for (int i = 0; i < image->phnum; i++) {
        const elf_segment_t *segment = (const void *)image + image->phoff + (size_t)image->phentsize * i;
        if (segment->segment_type != PT_LOAD || segment->memsz == 0) continue;
        if ((segment->vaddr | segment->offset) & PAGE_MASK) return ERR_INVALID_IMAGE;

        uintptr_t minv = segment->vaddr;
        uintptr_t maxv = minv + segment->memsz;
        if (maxv < minv) return ERR_INVALID_IMAGE;

        if (minv < min_vaddr) min_vaddr = minv;
        if (maxv > max_vaddr) max_vaddr = maxv;
    }

    if (min_vaddr > max_vaddr) {
        out->slide = 0;
        out->minv = 0;
        out->maxv = 0;
        return 0;
    }

    size_t size = max_vaddr - min_vaddr + extra;
    uintptr_t addr = 0;
    int error = vmm_add(&addr, size, 0, NULL, 0);
    if (error) return error;

    intptr_t slide = (intptr_t)addr - (intptr_t)min_vaddr;

    for (int i = 0; i < image->phnum; i++) {
        const elf_segment_t *segment = (const void *)image + image->phoff + (size_t)image->phentsize * i;
        if (segment->segment_type != PT_LOAD || segment->memsz == 0) continue;

        uintptr_t segment_addr = segment->vaddr + slide;
        size_t segment_size = (segment->memsz + PAGE_MASK) & ~PAGE_MASK;

        int flags = VMM_EXACT | VMM_PRIVATE;
        if (segment->flags & PF_R) flags |= VMM_READ;
        if (segment->flags & PF_W) flags |= VMM_WRITE;
        if (segment->flags & PF_X) flags |= VMM_EXEC;

        size_t filesz = (segment->filesz + PAGE_MASK) & ~PAGE_MASK;
        ASSERT(filesz <= segment_size);

        if (filesz != 0) {
            error = vmm_add(&segment_addr, filesz, flags, object, segment->offset);
            segment_addr += filesz;
            segment_size -= filesz;
        }

        if (error == 0 && segment_size != 0) {
            error = vmm_add(&segment_addr, segment_size, flags, NULL, 0);
        }

        if (error) {
            vmm_del(addr, size);
            return error;
        }
    }

    out->slide = slide;
    out->minv = min_vaddr + slide;
    out->maxv = max_vaddr + slide;
    return 0;
}
