#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/process.h>
#include <hydrogen/thread.h>
#include <hydrogen/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void iensure(int error) {
    if (error) {
        fprintf(stderr, "failed: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }
}

static hydrogen_ret_t ensure(hydrogen_ret_t ret) {
    iensure(ret.error);
    return ret;
}

static void spawn(const char *path) {
    hydrogen_ret_t image = ensure(hydrogen_fs_open(HYDROGEN_INVALID_HANDLE, path, strlen(path), 0, 0));
    hydrogen_ret_t ns = ensure(hydrogen_namespace_create(0));

    ensure(hydrogen_namespace_add(HYDROGEN_THIS_NAMESPACE, 0, ns.integer, 0, -1, HYDROGEN_REMOVE_HANDLE_FLAGS));
    ensure(hydrogen_namespace_add(HYDROGEN_THIS_NAMESPACE, 1, ns.integer, 1, -1, HYDROGEN_REMOVE_HANDLE_FLAGS));
    ensure(hydrogen_namespace_add(HYDROGEN_THIS_NAMESPACE, 2, ns.integer, 2, -1, HYDROGEN_REMOVE_HANDLE_FLAGS));

    hydrogen_ret_t proc = ensure(hydrogen_process_create(0));
    hydrogen_string_t arg0 = {path, strlen(path)};
    hydrogen_ret_t thread = ensure(hydrogen_thread_exec(proc.integer, ns.integer, image.integer, 1, &arg0, 0, NULL, 0));
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, thread.integer);
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ns.integer);
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, image.integer);
}

int main(void) {
    printf("Hello from proxima-init!\n");
    spawn("/usr/bin/proxima-devicesd");
    pause();
}
