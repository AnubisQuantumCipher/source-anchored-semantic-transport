/* TEST-ONLY Linux RNG fault injection, linked only into separate test binaries. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>

#ifndef SAST_TEST_RNG_FAIL_AFTER
#define SAST_TEST_RNG_FAIL_AFTER 0U
#endif

ssize_t __real_getrandom(void *buffer, size_t length, unsigned int flags);
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags);

ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags)
{
    static unsigned int calls = 0;
    calls++;
    if (calls > SAST_TEST_RNG_FAIL_AFTER) { errno = EIO; return -1; }
    return __real_getrandom(buffer, length, flags);
}
