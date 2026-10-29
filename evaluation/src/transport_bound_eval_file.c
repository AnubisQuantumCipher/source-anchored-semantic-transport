#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int transport_bound_read_frame(const char *path, unsigned char *data,
                               size_t capacity, size_t *used);

static int same_file(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode && before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int read_checked(int fd, unsigned char *data, size_t capacity,
                        const struct stat *before, size_t *used)
{
    struct stat after;
    size_t offset = 0;
    for (size_t attempt = 0; attempt < capacity + 1U; ++attempt) {
        const ssize_t count = read(fd, data + offset, capacity - offset);
        if (count < 0) {
            return -1; /* EINTR and every other read error fail closed. */
        }
        if (count == 0) {
            if (fstat(fd, &after) != 0 || !same_file(before, &after) ||
                offset != (size_t)before->st_size) {
                return -1;
            }
            *used = offset;
            return 0;
        }
        if ((size_t)count >= capacity - offset) {
            return -1; /* The extra byte detects growth beyond the frame cap. */
        }
        offset += (size_t)count; /* Positive progress, bounded by capacity. */
    }
    return -1;
}

int transport_bound_read_frame(const char *path, unsigned char *data,
                               size_t capacity, size_t *used)
{
    struct stat before;
    int result = -1;
    if (used == NULL) {
        return -1;
    }
    *used = 0;
    if (path == NULL || data == NULL || capacity < 1U || capacity > 4096U) {
        return -1;
    }
    /* Final-component symlinks are refused; parent path policy is the caller's. */
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_size >= 0 && before.st_size < (off_t)capacity) {
        result = read_checked(fd, data, capacity, &before, used);
    }
    if (close(fd) != 0) {
        result = -1;
    }
    if (result != 0) {
        *used = 0;
    }
    return result;
}
