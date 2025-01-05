#include "init/initrd.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "hydrogen/stat.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "string.h"
#include "util/panic.h"
#include "util/print.h"

typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
} __attribute__((packed)) ustar_header_t;

static uint64_t parse_oct(char *field, size_t size) {
    uint64_t value = 0;

    for (size_t i = 0; i < size; i++) {
        char c = field[i];
        if (c == 0 || c == ' ') break;
        value = (value * 8) + (c - '0');
    }

    return value;
}

static int open_dir(file_t *root, file_t **out, char **path, size_t *length) {
    char *name = *path;
    size_t len = *length;

    while (len > 0 && name[0] == '/') {
        name++;
        len--;
    }

    file_t *cur = root;
    file_ref(cur);

    while (len > 0) {
        size_t nlen = 1;
        while (nlen < len && name[nlen] != '/') nlen++;
        while (nlen < len && name[nlen] == '/') nlen++;

        if (nlen == len) break;

        file_t *child;
        int error = vfs_open(cur, &child, name, nlen, O_CREAT | O_DIRECTORY, 0755);
        if (unlikely(error)) {
            file_deref(cur);
            return error;
        }
        file_deref(cur);
        cur = child;

        name += nlen;
        len -= nlen;
    }

    *out = cur;
    *path = name;
    *length = len;
    return 0;
}

static int extract_record(file_t *dest, void *ptr, size_t *size, size_t *errors) {
    size_t avail = *size;
    if (avail < 512) return ERR_OVERFLOW;

    ustar_header_t *header = ptr;
    if (memcmp(header->magic, "ustar", sizeof(header->magic))) return ERR_OVERFLOW;
    if (memcmp(header->version, "00", sizeof(header->version))) return ERR_INVALID_IMAGE;

    uint32_t mode = parse_oct(header->mode, sizeof(header->mode)) & (S_ISUID | S_ISGID | S_IRWXUGO);
    uint32_t uid = parse_oct(header->uid, sizeof(header->uid));
    uint32_t gid = parse_oct(header->gid, sizeof(header->gid));
    uint64_t fsiz = parse_oct(header->size, sizeof(header->size));

    uint32_t blocks = 0;
    switch (header->typeflag) {
    case '1': break; // hard link
    case '2': mode |= S_IFLNK; break;
    case '3': mode |= S_IFCHR; break;
    case '4': mode |= S_IFBLK; break;
    case '5': mode |= S_IFDIR; break;
    case '6': mode |= S_IFIFO; break;
    case 0:
    case '0':
    case '7': mode |= S_IFREG; // fall through
    default: blocks = (fsiz + 511) / 512; break;
    }

    *size = (blocks + 1) * 512;
    if (*size > avail) {
        *size = avail;
        return ERR_INVALID_IMAGE;
    }

    char *name = header->name;
    size_t length = strnlen(header->name, sizeof(header->name));

    if (header->prefix[0] != 0) {
        size_t plen = strnlen(header->prefix, sizeof(header->prefix));
        char *path = vmalloc(length + plen);
        if (!path) return ERR_OUT_OF_MEMORY;
        memcpy(path, name, length);
        memcpy(path + length, header->prefix, plen);
        name = path;
        length += plen;
    }

    char *path = name;
    size_t plen = length;

    file_t *dir;
    int error = open_dir(dest, &dir, &name, &length);

    if (likely(error == 0)) {
        if (S_ISREG(mode)) {
            file_t *file;
            error = vfs_open(dir, &file, name, length, O_RDWR | O_CREAT, mode & ~S_IFMT);

            if (likely(error == 0)) {
                error = vfs_ftruncate(file, fsiz);

                if (likely(error == 0)) {
                    size_t total = fsiz;
                    void *buf = ptr + 512;

                    while (total > 0) {
                        size_t cur = total;
                        error = vfs_write(file, buf, &cur);
                        if (error) {
                            printk("initrd: %S: write failed (%d)\n", path, plen, error);
                            *errors += 1;
                            break;
                        }

                        buf += cur;
                        total -= cur;
                    }
                } else {
                    printk("initrd: %S: ftruncate failed (%d)\n", path, plen, error);
                    *errors += 1;
                }

                file_deref(file);
                error = 0;
            }
        } else if (S_ISLNK(mode)) {
            error = vfs_symlink(
                    dir,
                    name,
                    length,
                    header->linkname,
                    strnlen(header->linkname, sizeof(header->linkname))
            );
        } else if (header->typeflag == '1') {
            error = vfs_link(
                    dir,
                    name,
                    length,
                    dest,
                    header->linkname,
                    strnlen(header->linkname, sizeof(header->linkname)),
                    false
            );
        } else {
            error = vfs_mknod(dir, name, length, mode);
        }

        if ((error == 0 || error == ERR_ALREADY_EXISTS) && header->typeflag != '1') {
            error = vfs_chown(dir, name, length, uid, gid, false);
            if (error) {
                printk("initrd: %S: chown failed (%d)\n", path, plen, error);
                *errors += 1;
            }

            error = vfs_chmod(dir, name, length, mode, false);
            if (error) {
                printk("initrd: %S: chmod failed (%d)\n", path, plen, error);
                *errors += 1;
            }
        } else if (error != 0 && error != ERR_ALREADY_EXISTS) {
            printk("initrd: %S: creation failed (%d)\n", path, plen, error);
            *errors += 1;
        }

        file_deref(dir);
    } else {
        printk("initrd: %S: failed to open output directory (%d)\n", path, plen, error);
        *errors += 1;
    }

    if (header->prefix[0] != 0) vmfree(path, plen);

    return error;
}

static bool extract_initrd(file_t *dest, struct limine_file *module) {
    printk("initrd: extracting %s\n", module->path);

    uintptr_t addr;
    int error = kvmm_map_mmio(&addr, virt_to_phys(module->address), module->size, 0, CACHE_WRITEBACK);
    if (error) panic("initrd: failed to map initrd (%d)", error);

    void *ptr = (void *)addr;
    size_t remaining = module->size;
    size_t errors = 0;

    for (;;) {
        size_t cur = remaining;
        int error = extract_record(dest, ptr, &cur, &errors);
        if (unlikely(error)) {
            if (error == ERR_INVALID_IMAGE) printk("initrd: failed to extract file (%d)\n", error);
            if (error == ERR_OVERFLOW) break;
        }

        ptr += cur;
        remaining -= cur;
    }

    kvmm_unmap_mmio(addr, module->size);
    return errors;
}

void extract_initrds(file_t *rel, const char *path, size_t length) {
    static LIMINE_REQ struct limine_module_request module_req = {.id = LIMINE_MODULE_REQUEST};
    if (!module_req.response) return;

    struct limine_module_response *response = module_req.response;

    file_t *dest;
    int error = vfs_open(rel, &dest, path, length, O_CREAT | O_DIRECTORY, 0755);
    if (error) panic("failed to open extraction directory for initrds (%d)", error);

    size_t errors = 0;

    for (uint64_t i = 0; i < response->module_count; i++) {
        errors += extract_initrd(dest, response->modules[i]);
    }

    file_deref(dest);

    if (errors) panic("initrd: %U errors encountered during extraction", errors);
}
