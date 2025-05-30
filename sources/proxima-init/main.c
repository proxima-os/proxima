#include <errno.h>
#include <fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/process.h>
#include <hydrogen/thread.h>
#include <hydrogen/types.h>
#include <signal.h>
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
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ns.integer);
    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, image.integer);

    int error;
    siginfo_t info;

    while ((error = hydrogen_process_wait(
                proc.integer,
                HYDROGEN_PROCESS_WAIT_EXITED | HYDROGEN_PROCESS_WAIT_KILLED | HYDROGEN_PROCESS_WAIT_DISCARD |
                    HYDROGEN_PROCESS_WAIT_UNQUEUE,
                &info,
                0
            )) == EINTR);

    if (error) {
        fprintf(stderr, "init: failed to wait for devicesd: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }

    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);
}

int main(int argc, char *argv[]) {
    (void)argc;

    if (getpid() != 1) {
        fprintf(stderr, "%s: not running with PID 1\n", argv[0]);
        return 0;
    }

    // proxima-init is invoked with the standard streams backed by /dev/klog, which isn't a tty
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("Hello from proxima-init!\n");
    spawn("/usr/bin/proxima-devicesd");
    printf("devicesd init complete\n");

    int fd = open("/dev/console", O_RDWR);
    if (fd < 0) {
        perror("init: failed to open /dev/console");
        return EXIT_FAILURE;
    }

    fflush(stdin);
    fflush(stdout);
    fflush(stderr);

    if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) {
        perror("init: failed to set standard streams");
        return EXIT_FAILURE;
    }

    if (fd >= 3) close(fd);

    printf("transitioned to standard streams\n");

    pause();
}
