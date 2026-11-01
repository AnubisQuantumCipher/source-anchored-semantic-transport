/* Fixed, bounded glibc spawn bridge. No package data selects code or policy. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <spawn.h>
#include <string.h>

enum { FD_COUNT = 11, ARG_COUNT = 48, ARG_BYTES = 512, TOTAL_BYTES = 8192 };

static int checked_inputs(const int *fds, char *const *argv, size_t argc)
{
    size_t total = 0;
    if (fds == NULL || argv == NULL || argc == 0 || argc > ARG_COUNT)
        return EINVAL;
    for (size_t i = 0; i < FD_COUNT; i++)
        if (fds[i] < 32)
            return EBADF;
    for (size_t i = 0; i < argc; i++) {
        if (argv[i] == NULL)
            return EINVAL;
        size_t length = strnlen(argv[i], ARG_BYTES + 1);
        if (length > ARG_BYTES || total > TOTAL_BYTES - length)
            return E2BIG;
        total += length;
    }
    return argv[argc] == NULL ? 0 : EINVAL;
}

static int attributes(posix_spawnattr_t *attr)
{
    sigset_t empty, defaults;
    if (sigemptyset(&empty) != 0 || sigemptyset(&defaults) != 0)
        return errno;
    const int signals[] = { SIGCHLD, SIGINT, SIGTERM, SIGHUP, SIGALRM };
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
        if (sigaddset(&defaults, signals[i]) != 0)
            return errno;
    int rc = posix_spawnattr_setsigmask(attr, &empty);
    if (rc == 0)
        rc = posix_spawnattr_setsigdefault(attr, &defaults);
    if (rc == 0)
        rc = posix_spawnattr_setflags(attr, POSIX_SPAWN_SETSID |
                                     POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    return rc;
}

static int actions(posix_spawn_file_actions_t *list, const int *fds)
{
    for (int i = 0; i < FD_COUNT; i++) {
        int rc = posix_spawn_file_actions_adddup2(list, fds[i], i);
        if (rc != 0)
            return rc;
    }
    return posix_spawn_file_actions_addclosefrom_np(list, FD_COUNT);
}

/* pidfd is caller-owned, preallocated and registered before this function runs.
 * Even if cleanup below reports failure after spawn, the caller retains fd.
 * Kernel/exec scheduling is outside this bridge's termination claim. */
int sast_pidfd_spawn(int *pidfd, const int *fds, char *const *argv, size_t argc);
int sast_pidfd_spawn(int *pidfd, const int *fds, char *const *argv, size_t argc)
{
    if (pidfd == NULL || *pidfd != -1)
        return EINVAL;
    int rc = checked_inputs(fds, argv, argc);
    if (rc != 0)
        return rc;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t list;
    rc = posix_spawnattr_init(&attr);
    if (rc != 0)
        return rc;
    rc = posix_spawn_file_actions_init(&list);
    if (rc != 0) {
        int cleanup = posix_spawnattr_destroy(&attr);
        return cleanup == 0 ? rc : cleanup;
    }
    rc = attributes(&attr);
    if (rc == 0)
        rc = actions(&list, fds);
    char *const env[] = { "PATH=/usr/bin:/bin", "LANG=C", NULL };
    if (rc == 0)
        rc = pidfd_spawn(pidfd, "/proc/self/fd/8", &list, &attr, argv, env);
    int list_rc = posix_spawn_file_actions_destroy(&list);
    int attr_rc = posix_spawnattr_destroy(&attr);
    return rc != 0 ? rc : list_rc != 0 ? list_rc : attr_rc;
}
