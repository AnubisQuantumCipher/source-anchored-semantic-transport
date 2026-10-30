/* Additive admitted-key signer/verifier, with explicitly separate test keygen. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mldsa_native.h"

#define MESSAGE_CAP 8388608U
#define RNG_CALL_CAP 16U
static uint8_t message[MESSAGE_CAP];
static uint8_t public_key[MLDSA87_PUBLICKEYBYTES];
static uint8_t secret_key[MLDSA87_SECRETKEYBYTES];
static uint8_t signature[MLDSA87_BYTES];
static uint8_t second_signature[MLDSA87_BYTES];
static const uint8_t domain[] = "SAST-MANIFEST-MLDSA87-v1";

int randombytes(uint8_t *out, size_t outlen);

static void wipe(uint8_t *out, size_t length)
{
    volatile uint8_t *p = out;
    size_t i;
    for (i = 0; i < length; i++) { p[i] = 0; }
}

int randombytes(uint8_t *out, size_t outlen)
{
    size_t used = 0;
    unsigned int calls;
    if (outlen > MLDSA_SEEDBYTES) { return -1; }
    for (calls = 0; calls < RNG_CALL_CAP && used < outlen; calls++) {
        ssize_t n = getrandom(out + used, outlen - used, GRND_NONBLOCK);
        if (n > 0) { used += (size_t)n; }
        else if (n == 0 || errno != EINTR) { break; }
    }
    if (used != outlen) { wipe(out, outlen); return -1; }
    return 0;
}

static int read_exact(uint8_t *out, size_t length)
{
    return fread(out, 1, length, stdin) == length ? 0 : -1;
}

static int read_message(size_t *length)
{
    uint8_t header[4];
    uint32_t n;
    if (read_exact(header, sizeof(header)) != 0) { return -1; }
    n = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
        ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    if (n == 0 || n > MESSAGE_CAP) { return -1; }
    if (read_exact(message, n) != 0 || fgetc(stdin) != EOF || ferror(stdin)) {
        return -1;
    }
    *length = n;
    return 0;
}

static int ephemeral_sign(int twice)
{
    size_t length = 0;
    int result = sast_mldsa87_keypair(public_key, secret_key);
    if (result == 0 && (fwrite(public_key, 1, sizeof(public_key), stdout)
            != sizeof(public_key) || fflush(stdout) != 0)) { result = -1; }
    if (result == 0) { result = read_message(&length); }
    if (result == 0) {
        result = sast_mldsa87_signature(signature, message, length, domain,
                                       sizeof(domain) - 1, secret_key);
    }
    if (result == 0 && twice != 0) {
        result = sast_mldsa87_signature(second_signature, message, length, domain,
                                       sizeof(domain) - 1, secret_key);
    }
    wipe(secret_key, sizeof(secret_key));
    if (result == 0) {
        result = sast_mldsa87_verify(signature, message, length, domain,
                                   sizeof(domain) - 1, public_key);
    }
    if (result == 0 && twice != 0) {
        result = sast_mldsa87_verify(second_signature, message, length, domain,
                                   sizeof(domain) - 1, public_key);
        if (memcmp(signature, second_signature, sizeof(signature)) == 0) { result = -1; }
    }
    if (result == 0 && fwrite(signature, 1, sizeof(signature), stdout)
            != sizeof(signature)) { result = -1; }
    if (result == 0 && twice != 0 &&
        fwrite(second_signature, 1, sizeof(second_signature), stdout)
            != sizeof(second_signature)) { result = -1; }
    return result;
}

static int verify(void)
{
    size_t length = 0;
    if (read_exact(public_key, sizeof(public_key)) != 0 ||
        read_exact(signature, sizeof(signature)) != 0 ||
        read_message(&length) != 0) { return -1; }
    return sast_mldsa87_verify(signature, message, length, domain,
                              sizeof(domain) - 1, public_key);
}

static int key_descriptor(const char *text)
{
    char *end = NULL;
    unsigned long value;
    struct stat information;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || text[0] < '0' || text[0] > '9' || *end != '\0' ||
        value < 3 || value > 4095) { return -1; }
    if (fstat((int)value, &information) != 0 || !S_ISREG(information.st_mode) ||
        information.st_uid != geteuid() || (information.st_mode & 07777) > 0600 ||
        (information.st_mode & 0177) != 0 ||
        information.st_size != MLDSA87_SECRETKEYBYTES) { return -1; }
    return (int)value;
}

static int imported_sign(int descriptor)
{
    uint8_t derived[MLDSA87_PUBLICKEYBYTES];
    size_t length = 0;
    int result;
    if (pread(descriptor, secret_key, sizeof(secret_key), 0) != (ssize_t)sizeof(secret_key) ||
        read_exact(public_key, sizeof(public_key)) != 0 || read_message(&length) != 0) {
        return -1;
    }
    result = sast_mldsa87_pk_from_sk(derived, secret_key);
    if (result == 0 && memcmp(derived, public_key, sizeof(derived)) != 0) { result = -1; }
    if (result == 0) {
        result = sast_mldsa87_signature(signature, message, length, domain,
                                       sizeof(domain) - 1, secret_key);
    }
    wipe(secret_key, sizeof(secret_key));
    wipe(derived, sizeof(derived));
    if (result == 0) {
        result = sast_mldsa87_verify(signature, message, length, domain,
                                   sizeof(domain) - 1, public_key);
    }
    if (result == 0 && fwrite(signature, 1, sizeof(signature), stdout)
            != sizeof(signature)) { result = -1; }
    return result;
}

/* Explicit test-only key generator: private bytes go only to the supplied FD. */
static int test_keygen_to_fd(int descriptor)
{
    int result = sast_mldsa87_keypair(public_key, secret_key);
    if (result == 0 && pwrite(descriptor, secret_key, sizeof(secret_key), 0)
            != (ssize_t)sizeof(secret_key)) { result = -1; }
    wipe(secret_key, sizeof(secret_key));
    if (result == 0 && fwrite(public_key, 1, sizeof(public_key), stdout)
            != sizeof(public_key)) { result = -1; }
    return result;
}

static int limits(void)
{
    const struct rlimit no_core = {0, 0};
    const struct rlimit cpu = {10, 10};
    const struct rlimit memory = {67108864, 67108864};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 ||
        setrlimit(RLIMIT_CPU, &cpu) != 0 ||
        setrlimit(RLIMIT_AS, &memory) != 0) { return -1; }
    return 0;
}

int main(int argc, char **argv)
{
    int result = -1;
    if ((argc != 2 && argc != 3) || limits() != 0) { return 2; }
    if (argc == 2 && strcmp(argv[1], "ephemeral-test-sign") == 0) { result = ephemeral_sign(0); }
    else if (argc == 2 && strcmp(argv[1], "ephemeral-test-sign-twice") == 0) {
        result = ephemeral_sign(1);
    }
    else if (argc == 2 && strcmp(argv[1], "verify") == 0) { result = verify(); }
    else if (argc == 3) {
        int descriptor = key_descriptor(argv[2]);
        if (descriptor >= 0 && strcmp(argv[1], "sign-admitted-key-fd") == 0) {
            result = imported_sign(descriptor);
        }
        else if (descriptor >= 0 && strcmp(argv[1], "TEST-ONLY-keygen-to-fd") == 0) {
            result = test_keygen_to_fd(descriptor);
        }
    }
    wipe(secret_key, sizeof(secret_key));
    wipe(signature, sizeof(signature));
    wipe(second_signature, sizeof(second_signature));
    wipe(message, sizeof(message));
    if (fflush(stdout) != 0) { result = -1; }
    if (result != 0) { fputs("MLDSA87_PROVIDER_REFUSED\n", stderr); return 1; }
    return 0;
}
