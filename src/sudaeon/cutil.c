/*
 * cutil.c - shared C helpers for Sudaeon (see cutil.h).
 *
 * No external dependencies: SHA-256, HMAC, PBKDF2, scrypt, the policy parser,
 * the rate limiter and the audit writer are all implemented here so that the
 * setuid checker and the PAM module build on a machine with nothing but a C
 * compiler and glibc.
 */

#define _GNU_SOURCE
#include "cutil.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SD_STATE_DIR "/var/lib/sudaeon"
#define SD_LOCKOUT_FILE "/var/lib/sudaeon/lockout.json"
#define SD_VERIFIER_FILE "/var/lib/sudaeon/master.verifier"
#define SD_RECOVERY_FILE "/var/lib/sudaeon/recovery.verifier"
#define SD_CONF_FILE "/var/lib/sudaeon/enforcement.conf"
#define SD_MARKER_FILE "/var/lib/sudaeon/installed.json"
#define SD_AUDIT_FILE "/var/log/sudaeon/audit.log"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Path resolution.  The test-suite (which runs unprivileged) can point the
 * library at a temporary directory with SUDAEON_STATE_DIR / SUDAEON_AUDIT_LOG.
 * The override is ignored for setuid processes and for root, so it can never
 * be used to redirect a privileged program.
 */
static const char *sd_env_override(const char *name)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return NULL;
    }
    if (geteuid() != getuid() || geteuid() == 0 || getuid() == 0) {
        return NULL;
    }
    return value;
}

static const char *sd_state_path(const char *name, char *buf, size_t buflen)
{
    const char *dir = sd_env_override("SUDAEON_STATE_DIR");
    if (dir != NULL) {
        snprintf(buf, buflen, "%s/%s", dir, name);
    } else {
        snprintf(buf, buflen, "%s/%s", SD_STATE_DIR, name);
    }
    return buf;
}

static const char *sd_audit_path(char *buf, size_t buflen)
{
    const char *path = sd_env_override("SUDAEON_AUDIT_LOG");
    if (path != NULL) {
        snprintf(buf, buflen, "%s", path);
    } else {
        snprintf(buf, buflen, "%s", SD_AUDIT_FILE);
    }
    return buf;
}

/* ================================================================== */
/* SHA-256                                                             */
/* ================================================================== */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint32_t datalen;
    uint8_t data[64];
} sd_sha256_ctx;

static const uint32_t SD_K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SD_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SD_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SD_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SD_EP0(x) (SD_ROTR(x, 2) ^ SD_ROTR(x, 13) ^ SD_ROTR(x, 22))
#define SD_EP1(x) (SD_ROTR(x, 6) ^ SD_ROTR(x, 11) ^ SD_ROTR(x, 25))
#define SD_SIG0(x) (SD_ROTR(x, 7) ^ SD_ROTR(x, 18) ^ ((x) >> 3))
#define SD_SIG1(x) (SD_ROTR(x, 17) ^ SD_ROTR(x, 19) ^ ((x) >> 10))

static void sd_sha256_transform(sd_sha256_ctx *ctx, const uint8_t data[64])
{
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        m[i] = SD_SIG1(m[i - 2]) + m[i - 7] + SD_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SD_EP1(e) + SD_CH(e, f, g) + SD_K256[i] + m[i];
        t2 = SD_EP0(a) + SD_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sd_sha256_init(sd_sha256_ctx *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sd_sha256_update(sd_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sd_sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sd_sha256_final(sd_sha256_ctx *ctx, uint8_t hash[32])
{
    uint32_t i = ctx->datalen;
    uint64_t bits = ctx->bitlen + (uint64_t)ctx->datalen * 8;
    uint8_t pad[72];
    int padlen;
    int j;

    pad[0] = 0x80;
    padlen = (i < 56) ? (56 - (int)i) : (120 - (int)i);
    for (j = 1; j < padlen; j++) {
        pad[j] = 0x00;
    }
    for (j = 0; j < 8; j++) {
        pad[padlen + j] = (uint8_t)(bits >> (56 - 8 * j));
    }

    sd_sha256_update(ctx, pad, (size_t)padlen + 8);

    for (i = 0; i < 4; i++) {
        hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

void sd_sha256(const void *data, size_t len, uint8_t out[32])
{
    sd_sha256_ctx ctx;
    sd_sha256_init(&ctx);
    sd_sha256_update(&ctx, (const uint8_t *)data, len);
    sd_sha256_final(&ctx, out);
}

void sd_sha256_hex(const void *data, size_t len, char out[65])
{
    static const char *hex = "0123456789abcdef";
    uint8_t digest[32];
    int i;
    sd_sha256(data, len, digest);
    for (i = 0; i < 32; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

/* ================================================================== */
/* HMAC-SHA-256                                                        */
/* ================================================================== */

void sd_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[32])
{
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[32];
    sd_sha256_ctx ctx;
    size_t i;

    memset(k, 0, sizeof(k));
    if (keylen > 64) {
        sd_sha256(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    sd_sha256_init(&ctx);
    sd_sha256_update(&ctx, ipad, 64);
    sd_sha256_update(&ctx, msg, msglen);
    sd_sha256_final(&ctx, inner);

    sd_sha256_init(&ctx);
    sd_sha256_update(&ctx, opad, 64);
    sd_sha256_update(&ctx, inner, 32);
    sd_sha256_final(&ctx, out);
}

/* ================================================================== */
/* PBKDF2-HMAC-SHA-256 (RFC 2898)                                      */
/* ================================================================== */

int sd_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t rounds, uint8_t *out, size_t outlen)
{
    uint32_t block = 1;
    size_t produced = 0;
    uint8_t *blockbuf;
    uint8_t u[32];
    uint8_t t[32];
    size_t i;

    if (rounds == 0 || outlen == 0) {
        return SD_ERR_USAGE;
    }
    blockbuf = malloc(saltlen + 4);
    if (blockbuf == NULL) {
        return SD_ERR_MEMORY;
    }

    while (produced < outlen) {
        uint32_t be = ((block & 0xff) << 24) | (((block >> 8) & 0xff) << 16) |
                      (((block >> 16) & 0xff) << 8) | ((block >> 24) & 0xff);
        uint32_t round;

        memcpy(blockbuf, salt, saltlen);
        memcpy(blockbuf + saltlen, &be, 4);
        sd_hmac_sha256(pass, passlen, blockbuf, saltlen + 4, u);
        memcpy(t, u, 32);
        for (round = 1; round < rounds; round++) {
            sd_hmac_sha256(pass, passlen, u, 32, u);
            for (i = 0; i < 32; i++) {
                t[i] ^= u[i];
            }
        }
        for (i = 0; i < 32 && produced < outlen; i++, produced++) {
            out[produced] = t[i];
        }
        block++;
    }
    free(blockbuf);
    return SD_OK;
}

/* ================================================================== */
/* Salsa20/8 core, scryptBlockMix, scryptROMix, scrypt                 */
/* ================================================================== */

#define SD_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * The Salsa20/8 core, kept in the reference form published in RFC 7914 and
 * the original scrypt source: one output word is taken from the state after
 * the column rounds, the other from the state after the row rounds.
 */
static void sd_salsa20_8_words(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x[16];
    int i;

    memcpy(x, in, 64);
    for (i = 0; i < 8; i += 2) {
        x[4] ^= SD_ROTL((x[0] + x[12]) & 0xffffffffU, 7);
        x[8] ^= SD_ROTL((x[4] + x[0]) & 0xffffffffU, 9);
        x[12] ^= SD_ROTL((x[8] + x[4]) & 0xffffffffU, 13);
        x[0] ^= SD_ROTL((x[12] + x[8]) & 0xffffffffU, 18);

        x[9] ^= SD_ROTL((x[5] + x[1]) & 0xffffffffU, 7);
        x[13] ^= SD_ROTL((x[9] + x[5]) & 0xffffffffU, 9);
        x[1] ^= SD_ROTL((x[13] + x[9]) & 0xffffffffU, 13);
        x[5] ^= SD_ROTL((x[1] + x[13]) & 0xffffffffU, 18);

        x[14] ^= SD_ROTL((x[10] + x[6]) & 0xffffffffU, 7);
        x[2] ^= SD_ROTL((x[14] + x[10]) & 0xffffffffU, 9);
        x[6] ^= SD_ROTL((x[2] + x[14]) & 0xffffffffU, 13);
        x[10] ^= SD_ROTL((x[6] + x[2]) & 0xffffffffU, 18);

        x[3] ^= SD_ROTL((x[15] + x[11]) & 0xffffffffU, 7);
        x[7] ^= SD_ROTL((x[3] + x[15]) & 0xffffffffU, 9);
        x[11] ^= SD_ROTL((x[7] + x[3]) & 0xffffffffU, 13);
        x[15] ^= SD_ROTL((x[11] + x[7]) & 0xffffffffU, 18);

        x[1] ^= SD_ROTL((x[0] + x[3]) & 0xffffffffU, 7);
        x[2] ^= SD_ROTL((x[1] + x[0]) & 0xffffffffU, 9);
        x[3] ^= SD_ROTL((x[2] + x[1]) & 0xffffffffU, 13);
        x[0] ^= SD_ROTL((x[3] + x[2]) & 0xffffffffU, 18);

        x[6] ^= SD_ROTL((x[5] + x[4]) & 0xffffffffU, 7);
        x[7] ^= SD_ROTL((x[6] + x[5]) & 0xffffffffU, 9);
        x[4] ^= SD_ROTL((x[7] + x[6]) & 0xffffffffU, 13);
        x[5] ^= SD_ROTL((x[4] + x[7]) & 0xffffffffU, 18);

        x[11] ^= SD_ROTL((x[10] + x[9]) & 0xffffffffU, 7);
        x[8] ^= SD_ROTL((x[11] + x[10]) & 0xffffffffU, 9);
        x[9] ^= SD_ROTL((x[8] + x[11]) & 0xffffffffU, 13);
        x[10] ^= SD_ROTL((x[9] + x[8]) & 0xffffffffU, 18);

        x[12] ^= SD_ROTL((x[15] + x[14]) & 0xffffffffU, 7);
        x[13] ^= SD_ROTL((x[12] + x[15]) & 0xffffffffU, 9);
        x[14] ^= SD_ROTL((x[13] + x[12]) & 0xffffffffU, 13);
        x[15] ^= SD_ROTL((x[14] + x[13]) & 0xffffffffU, 18);
    }
    for (i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

void sd_salsa20_8(uint8_t block[64])
{
    uint32_t in[16];
    uint32_t out[16];
    int i;

    for (i = 0; i < 16; i++) {
        in[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
                ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }
    sd_salsa20_8_words(out, in);
    for (i = 0; i < 16; i++) {
        block[i * 4] = (uint8_t)(out[i] & 0xff);
        block[i * 4 + 1] = (uint8_t)((out[i] >> 8) & 0xff);
        block[i * 4 + 2] = (uint8_t)((out[i] >> 16) & 0xff);
        block[i * 4 + 3] = (uint8_t)((out[i] >> 24) & 0xff);
    }
}

/*
 * scryptBlockMix (RFC 7914 section 4):  Y[j] = H(X xor B[j]) with X carried
 * over from the previous step, and the result written as
 * (Y_0, Y_2, ..., Y_{2r-2}, Y_1, Y_3, ..., Y_{2r-1}).
 * `scratch` must hold 2*r*64 bytes.
 */
void sd_blockmix(const uint32_t *b, uint32_t *y, uint32_t *scratch,
                 uint32_t r)
{
    uint32_t x[16];
    uint32_t two_r = 2 * r;
    uint32_t i, j;

    memcpy(x, &b[(two_r - 1) * 16], 64);
    for (i = 0; i < two_r; i++) {
        for (j = 0; j < 16; j++) {
            x[j] ^= b[i * 16 + j];
        }
        sd_salsa20_8_words(x, x);
        memcpy(&scratch[i * 16], x, 64);
    }
    for (i = 0; i < r; i++) {
        memcpy(&y[i * 16], &scratch[(2 * i) * 16], 64);
    }
    for (i = 0; i < r; i++) {
        memcpy(&y[(r + i) * 16], &scratch[(2 * i + 1) * 16], 64);
    }
}

/* scryptROMix (RFC 7914 section 5). */
int sd_romix(uint32_t *block, uint32_t n, uint32_t r)
{
    uint32_t words = 32 * r;
    uint32_t *x = NULL, *y = NULL, *scratch = NULL, *v = NULL;
    uint32_t i, j, k;

    x = malloc(sizeof(uint32_t) * words);
    y = malloc(sizeof(uint32_t) * words);
    scratch = malloc(sizeof(uint32_t) * 2 * words);
    if (n > 0 && n <= (uint32_t)(SIZE_MAX / (sizeof(uint32_t) * words))) {
        v = malloc(sizeof(uint32_t) * (size_t)words * n);
    }
    if (!x || !y || !scratch || !v) {
        free(x); free(y); free(scratch); free(v);
        return SD_ERR_MEMORY;
    }

    memcpy(x, block, sizeof(uint32_t) * words);
    for (i = 0; i < n; i++) {
        memcpy(&v[(size_t)i * words], x, sizeof(uint32_t) * words);
        sd_blockmix(x, y, scratch, r);
        memcpy(x, y, sizeof(uint32_t) * words);
    }
    for (i = 0; i < n; i++) {
        j = x[(2 * r - 1) * 16] & (n - 1);
        for (k = 0; k < words; k++) {
            x[k] ^= v[(size_t)j * words + k];
        }
        sd_blockmix(x, y, scratch, r);
        memcpy(x, y, sizeof(uint32_t) * words);
    }
    memcpy(block, x, sizeof(uint32_t) * words);
    free(x); free(y); free(scratch); free(v);
    return SD_OK;
}

int sd_scrypt(const uint8_t *pass, size_t passlen,
              const uint8_t *salt, size_t saltlen,
              uint32_t n, uint32_t r, uint32_t p,
              uint8_t *out, size_t outlen)
{
    uint8_t *b = NULL;
    uint32_t i, j;
    uint32_t blocksize;
    int rc = SD_OK;

    if (n < 2 || (n & (n - 1)) != 0) {
        return SD_ERR_USAGE;
    }
    if (r == 0 || p == 0 || outlen == 0 || p > 16 || r > 32) {
        return SD_ERR_USAGE;
    }
    if (n > SD_MAX_N) {
        return SD_ERR_USAGE;
    }
    if (r > 0 && n > (uint32_t)(SIZE_MAX / (128u * r))) {
        return SD_ERR_USAGE;
    }
    blocksize = 128 * r;

    rc = sd_pbkdf2_hmac_sha256(pass, passlen, salt, saltlen, 1, out, outlen);
    if (rc != SD_OK) {
        return rc;
    }
    b = malloc((size_t)blocksize * p);
    if (b == NULL) {
        return SD_ERR_MEMORY;
    }
    rc = sd_pbkdf2_hmac_sha256(pass, passlen, salt, saltlen, 1, b,
                               (size_t)blocksize * p);
    if (rc != SD_OK) {
        free(b);
        return rc;
    }
    for (i = 0; i < p; i++) {
        uint32_t *words = (uint32_t *)(void *)(b + (size_t)i * blocksize);
        rc = sd_romix(words, n, r);
        if (rc != SD_OK) {
            free(b);
            return rc;
        }
    }
    rc = sd_pbkdf2_hmac_sha256(pass, passlen, b, (size_t)blocksize * p, 1, out, outlen);
    for (j = 0; j < (size_t)blocksize * p; j++) {
        b[j] = 0;
    }
    free(b);
    return rc;
}

int sd_constant_time_eq(const void *a, const void *b, size_t len)
{
    const uint8_t *x = a;
    const uint8_t *y = b;
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return diff == 0;
}

/* ================================================================== */
/* small file helpers                                                  */
/* ================================================================== */

int sd_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

int sd_read_file(const char *path, char *out, size_t outlen)
{
    int fd;
    ssize_t got;
    size_t used = 0;

    if (outlen == 0) {
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    while (used + 1 < outlen) {
        got = read(fd, out + used, outlen - 1 - used);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (got == 0) {
            break;
        }
        used += (size_t)got;
    }
    out[used] = '\0';
    close(fd);
    return (int)used;
}

int sd_write_file(const char *path, const char *text, mode_t mode)
{
    char tmp[SD_PATH_MAX + 16];
    int fd;
    size_t len = strlen(text);
    ssize_t written;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) >= (int)sizeof(tmp)) {
        return SD_ERR_IO;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        return SD_ERR_IO;
    }
    written = write(fd, text, len);
    if (written < 0 || (size_t)written != len) {
        close(fd);
        unlink(tmp);
        return SD_ERR_IO;
    }
    if (fsync(fd) != 0) {
        /* not fatal: some filesystems refuse fsync on special files */
    }
    close(fd);
    if (chmod(tmp, mode) != 0) {
        /* best effort */
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return SD_ERR_IO;
    }
    return SD_OK;
}

int sd_read_line(int fd, char *out, size_t outlen)
{
    size_t used = 0;
    char c;
    ssize_t got;

    if (outlen == 0) {
        return -1;
    }
    while (used + 1 < outlen) {
        got = read(fd, &c, 1);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            break;
        }
        if (c == '\n') {
            break;
        }
        if (c == '\r') {
            continue;
        }
        out[used++] = c;
    }
    out[used] = '\0';
    return (int)used;
}

int sd_read_secret(int fd, char *out, size_t outlen)
{
    struct termios saved, raw;
    int is_tty = isatty(fd);
    int restored = 0;
    int rc;

    if (is_tty && tcgetattr(fd, &saved) == 0) {
        raw = saved;
        raw.c_lflag &= (tcflag_t)~ECHO;
        raw.c_lflag &= (tcflag_t)~ECHONL;
        if (tcsetattr(fd, TCSAFLUSH, &raw) == 0) {
            restored = 1;
        }
    }
    rc = sd_read_line(fd, out, outlen);
    if (restored) {
        tcsetattr(fd, TCSAFLUSH, &saved);
        fputc('\n', stderr);
    }
    return rc;
}

/* ================================================================== */
/* identity, time                                                      */
/* ================================================================== */

int sd_is_root(void)
{
    return geteuid() == 0;
}

const char *sd_username(void)
{
    static char name[SD_USER_NAME_MAX];
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        snprintf(name, sizeof(name), "uid%u", (unsigned)getuid());
    } else {
        snprintf(name, sizeof(name), "%s", pw->pw_name);
    }
    return name;
}

void sd_now_iso(char *buf, size_t buflen)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ================================================================== */
/* audit log                                                           */
/* ================================================================== */

static char sd_audit_extra_key[64];
static char sd_audit_extra_value[256];

void sd_audit_set_extra(const char *key, const char *value)
{
    snprintf(sd_audit_extra_key, sizeof(sd_audit_extra_key), "%s", key ? key : "");
    snprintf(sd_audit_extra_value, sizeof(sd_audit_extra_value), "%s", value ? value : "");
}

static void sd_json_escape(const char *text, char *out, size_t outlen)
{
    size_t used = 0;
    size_t i;
    for (i = 0; text != NULL && text[i] != '\0' && used + 7 < outlen; i++) {
        unsigned char c = (unsigned char)text[i];
        switch (c) {
        case '"': out[used++] = '\\'; out[used++] = '"'; break;
        case '\\': out[used++] = '\\'; out[used++] = '\\'; break;
        case '\n': out[used++] = '\\'; out[used++] = 'n'; break;
        case '\r': out[used++] = '\\'; out[used++] = 'r'; break;
        case '\t': out[used++] = '\\'; out[used++] = 't'; break;
        default:
            if (c < 0x20) {
                used += (size_t)snprintf(out + used, outlen - used, "\\u%04x", c);
            } else {
                out[used++] = (char)c;
            }
        }
    }
    out[used] = '\0';
}

void sd_audit(const char *action, const char *result, const char *source,
              const char *detail)
{
    char path[SD_PATH_MAX];
    char stamp[32];
    char user[SD_USER_NAME_MAX];
    char escaped[512];
    char line[1024];
    char escaped_key[128];
    char escaped_detail[512];
    char escaped_extra[512];
    int fd;
    int used;

    sd_now_iso(stamp, sizeof(stamp));
    snprintf(user, sizeof(user), "%s", sd_username());
    sd_json_escape(user, escaped, sizeof(escaped));
    sd_json_escape(detail, escaped_detail, sizeof(escaped_detail));
    sd_json_escape(sd_audit_extra_key, escaped_key, sizeof(escaped_key));
    sd_json_escape(sd_audit_extra_value, escaped_extra, sizeof(escaped_extra));

    used = snprintf(line, sizeof(line),
                    "{\"ts\":\"%s\",\"action\":\"%s\",\"result\":\"%s\","
                    "\"user\":\"%s\",\"uid\":%u,\"source\":\"%s\",\"pid\":%d",
                    stamp, action ? action : "unknown", result ? result : "info",
                    escaped, (unsigned)getuid(), source ? source : "c", (int)getpid());
    if (detail != NULL && detail[0] != '\0' && used > 0 && used < (int)sizeof(line)) {
        used += snprintf(line + used, sizeof(line) - (size_t)used,
                         ",\"detail\":\"%s\"", escaped_detail);
    }
    if (sd_audit_extra_key[0] != '\0' && used > 0 && used < (int)sizeof(line)) {
        used += snprintf(line + used, sizeof(line) - (size_t)used,
                         ",\"extra\":{\"%s\":\"%s\"}", escaped_key, escaped_extra);
    }
    if (used > 0 && used < (int)sizeof(line) - 2) {
        line[used++] = '}';
        line[used++] = '\n';
        line[used] = '\0';
    } else {
        return;
    }

    fd = open(sd_audit_path(path, sizeof(path)), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
              0600);
    if (fd < 0) {
        return;
    }
    if (flock(fd, LOCK_EX) == 0) {
        if (write(fd, line, (size_t)used) < 0) {
            /* nothing sensible to do */
        }
        flock(fd, LOCK_UN);
    }
    close(fd);
}

/* ================================================================== */
/* rate limiting                                                       */
/* ================================================================== */

struct sd_lock_state {
    uint32_t fails;
    uint32_t last_fail;
    uint32_t locked_until;
};

/*: the first lockout, and the largest one the rate limiter will hand out. */
#define SD_LOCK_BASE 30u
#define SD_LOCK_MAX 1800u
/*: after this much quiet time the counter starts over. */
#define SD_LOCK_DECAY 3600u

static void sd_lock_read(struct sd_lock_state *state)
{
    char path[SD_PATH_MAX];
    char buffer[512];
    char *line;

    memset(state, 0, sizeof(*state));
    if (sd_read_file(sd_state_path("lockout.json", path, sizeof(path)),
                     buffer, sizeof(buffer)) < 0) {
        return;
    }
    for (line = strtok(buffer, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        if (strncmp(line, "fails=", 6) == 0) {
            state->fails = (uint32_t)strtoul(line + 6, NULL, 10);
        } else if (strncmp(line, "last_fail=", 10) == 0) {
            state->last_fail = (uint32_t)strtoul(line + 10, NULL, 10);
        } else if (strncmp(line, "locked_until=", 13) == 0) {
            state->locked_until = (uint32_t)strtoul(line + 13, NULL, 10);
        }
    }
}

static void sd_lock_write(const struct sd_lock_state *state)
{
    char path[SD_PATH_MAX];
    char buffer[256];

    snprintf(buffer, sizeof(buffer), "fails=%u\nlast_fail=%u\nlocked_until=%u\n",
             state->fails, state->last_fail, state->locked_until);
    if (sd_write_file(sd_state_path("lockout.json", path, sizeof(path)), buffer,
                      0600) < 0) {
        /* the caller cannot do anything sensible about this */
    }
}

int sd_lockout_locked(uint32_t *remaining)
{
    struct sd_lock_state state;
    uint32_t now = (uint32_t)time(NULL);

    sd_lock_read(&state);
    if (state.locked_until > now) {
        if (remaining != NULL) {
            *remaining = state.locked_until - now;
        }
        return 1;
    }
    if (remaining != NULL) {
        *remaining = 0;
    }
    return 0;
}

/*
 * Record one failed attempt.  The first `max_attempts` failures are free, the
 * next one locks the account for 30 seconds and every further failure doubles
 * the wait (30, 60, 120, ... capped at 1800).  Returns the number of failures
 * recorded so far, which is what the audit log stores.
 */
int sd_lockout_fail(uint32_t max_attempts, int *locked_now, uint32_t *seconds)
{
    struct sd_lock_state state;
    uint32_t now = (uint32_t)time(NULL);
    uint32_t limit = max_attempts == 0 ? 3u : max_attempts;
    uint32_t extra;
    uint32_t wait;

    sd_lock_read(&state);
    if (state.last_fail != 0 && now > state.last_fail + SD_LOCK_DECAY) {
        state.fails = 0;
    }
    state.fails++;
    state.last_fail = now;

    if (state.fails >= limit) {
        extra = state.fails - limit;
        if (extra > 6) {
            extra = 6;
        }
        wait = SD_LOCK_BASE << extra;
        if (wait > SD_LOCK_MAX) {
            wait = SD_LOCK_MAX;
        }
        state.locked_until = now + wait;
        if (locked_now != NULL) {
            *locked_now = 1;
        }
        if (seconds != NULL) {
            *seconds = wait;
        }
    } else {
        if (locked_now != NULL) {
            *locked_now = 0;
        }
        if (seconds != NULL) {
            *seconds = 0;
        }
    }
    sd_lock_write(&state);
    return (int)state.fails;
}

void sd_lockout_clear(void)
{
    struct sd_lock_state state;

    memset(&state, 0, sizeof(state));
    sd_lock_write(&state);
}

int sd_lockout_status(uint32_t *fails, uint32_t *remaining)
{
    struct sd_lock_state state;
    uint32_t now = (uint32_t)time(NULL);

    sd_lock_read(&state);
    if (fails != NULL) {
        *fails = state.fails;
    }
    if (state.locked_until > now) {
        if (remaining != NULL) {
            *remaining = state.locked_until - now;
        }
        return 1;
    }
    if (remaining != NULL) {
        *remaining = 0;
    }
    return 0;
}

/* ================================================================== */
/* verifier records                                                    */
/* ================================================================== */

#define SD_VERIFIER_PREFIX "SUDAEON-VERIFIER-V1"
#define SD_RECOVERY_PREFIX "SUDAEON-RECOVERY-V1"

static const char *sd_recovery_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/* Reads a JSON string value.  Returns the length, or -1. */
static int sd_json_string(const char *json, const char *key, char *out, size_t outlen)
{
    char pattern[48];
    const char *found;
    size_t length = 0;

    if (json == NULL || key == NULL || out == NULL || outlen == 0) {
        return -1;
    }
    out[0] = '\0';
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    found = strstr(json, pattern);
    if (found == NULL) {
        return -1;
    }
    found += strlen(pattern);
    while (*found == ' ' || *found == '\t' || *found == ':') {
        found++;
    }
    if (*found != '"') {
        return -1;
    }
    found++;
    while (*found != '\0' && *found != '"' && length + 1 < outlen) {
        out[length++] = *found++;
    }
    out[length] = '\0';
    return *found == '"' ? (int)length : -1;
}

/* Reads a JSON integer value.  Returns 0 on success. */
static int sd_json_int(const char *json, const char *key, long *out)
{
    char pattern[48];
    const char *found;
    char *end = NULL;
    long value;

    if (json == NULL || key == NULL || out == NULL) {
        return -1;
    }
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    found = strstr(json, pattern);
    if (found == NULL) {
        return -1;
    }
    found += strlen(pattern);
    while (*found == ' ' || *found == '\t' || *found == ':') {
        found++;
    }
    value = strtol(found, &end, 10);
    if (end == found) {
        return -1;
    }
    *out = value;
    return 0;
}

/* Decodes hex text.  Returns the number of bytes, or -1. */
static int sd_hex_decode(const char *text, uint8_t *out, size_t outlen)
{
    size_t length;
    size_t i;

    if (text == NULL) {
        return -1;
    }
    length = strlen(text);
    if (length == 0 || length % 2 != 0 || length / 2 > outlen) {
        return -1;
    }
    for (i = 0; i < length; i++) {
        int value;
        char character = text[i];
        if (character >= '0' && character <= '9') {
            value = character - '0';
        } else if (character >= 'a' && character <= 'f') {
            value = character - 'a' + 10;
        } else if (character >= 'A' && character <= 'F') {
            value = character - 'A' + 10;
        } else {
            return -1;
        }
        if (i % 2 == 0) {
            out[i / 2] = (uint8_t)(value << 4);
        } else {
            out[i / 2] |= (uint8_t)value;
        }
    }
    return (int)(length / 2);
}


/*
 * The master verifier is the JSON record written by sudaeon.crypto:
 *
 *   {"version":1,"kdf":"scrypt","n":32768,"r":8,"p":1,"dklen":32,
 *    "salt":"<hex>","hash":"<sha256 hex of SUDAEON-VERIFIER-V1||key>"}
 *
 * Returns SD_OK (0) when the password matches, 1 when it does not, and 2 when
 * the record is missing or unusable.  `detail` receives a short explanation.
 */
int sd_master_verify(const char *password, char *detail, size_t detail_len)
{
    char path[SD_PATH_MAX];
    char json[2048];
    char kdf[32];
    char salt_hex[SD_SALT_MAX * 2 + 2];
    char hash_hex[SD_HASH_MAX * 2 + 2];
    uint8_t salt[SD_SALT_MAX];
    uint8_t expected[SD_HASH_MAX];
    uint8_t key[SD_HASH_MAX];
    uint8_t payload[sizeof(SD_VERIFIER_PREFIX) - 1 + SD_HASH_MAX];
    uint8_t digest[32];
    long n = 0, r = 0, p = 0, dklen = 32;
    int salt_length;
    int hash_length;
    int key_length;

    if (detail != NULL && detail_len > 0) {
        detail[0] = '\0';
    }
    if (password == NULL) {
        password = "";
    }
    if (sd_read_file(sd_state_path("master.verifier", path, sizeof(path)),
                     json, sizeof(json)) < 0) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master password is not configured");
        }
        return 2;
    }
    snprintf(kdf, sizeof(kdf), "scrypt");
    sd_json_string(json, "kdf", kdf, sizeof(kdf));
    if (strcmp(kdf, "scrypt") != 0 ||
        sd_json_int(json, "n", &n) != 0 || sd_json_int(json, "r", &r) != 0 ||
        sd_json_int(json, "p", &p) != 0) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master verifier is unreadable");
        }
        return 2;
    }
    if (sd_json_int(json, "dklen", &dklen) != 0) {
        dklen = 32;
    }
    if (sd_json_string(json, "salt", salt_hex, sizeof(salt_hex)) < 0 ||
        sd_json_string(json, "hash", hash_hex, sizeof(hash_hex)) < 0) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master verifier is unreadable");
        }
        return 2;
    }
    if (n < 2 || n > (long)SD_MAX_N || r < 1 || r > 1024 || p < 1 || p > 64 ||
        dklen < 16 || dklen > (long)SD_HASH_MAX) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master verifier uses unsupported parameters");
        }
        return 2;
    }
    salt_length = sd_hex_decode(salt_hex, salt, sizeof(salt));
    hash_length = sd_hex_decode(hash_hex, expected, sizeof(expected));
    if (salt_length <= 0 || hash_length != 32) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master verifier is unreadable");
        }
        return 2;
    }

    key_length = sd_scrypt((const uint8_t *)password, strlen(password), salt,
                           (size_t)salt_length, (uint32_t)n, (uint32_t)r,
                           (uint32_t)p, key, (size_t)dklen);
    if (key_length != SD_OK) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the master password could not be verified");
        }
        return 2;
    }
    memcpy(payload, SD_VERIFIER_PREFIX, sizeof(SD_VERIFIER_PREFIX) - 1);
    memcpy(payload + sizeof(SD_VERIFIER_PREFIX) - 1, key, (size_t)dklen);
    sd_sha256(payload, sizeof(SD_VERIFIER_PREFIX) - 1 + (size_t)dklen, digest);
    memset(key, 0, sizeof(key));

    if (sd_constant_time_eq(digest, expected, 32) == 1) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "accepted");
        }
        return SD_OK;
    }
    if (detail != NULL && detail_len > 0) {
        snprintf(detail, detail_len, "the password is incorrect");
    }
    return 1;
}

/*
 * The recovery verifier is sha256("SUDAEON-RECOVERY-V1" || normalized key) of
 * the 20 character key that was shown during setup.  The key is normalised
 * exactly like sudaeon.crypto.normalize_recovery_key(): upper case, no dashes
 * or spaces, I/L -> 1, O -> 0, U -> V, and only Crockford characters survive.
 */
static void sd_normalize_recovery_key(const char *text, char *out, size_t outlen)
{
    size_t used = 0;

    for (; text != NULL && *text != '\0' && used + 1 < outlen; text++) {
        unsigned char character = (unsigned char)*text;
        if (character >= 'a' && character <= 'z') {
            character = (unsigned char)(character - 'a' + 'A');
        }
        if (character == 'I' || character == 'L') {
            character = '1';
        } else if (character == 'O') {
            character = '0';
        } else if (character == 'U') {
            character = 'V';
        }
        if (strchr(sd_recovery_alphabet, (char)character) != NULL) {
            out[used++] = (char)character;
        }
    }
    if (outlen > 0) {
        out[used] = '\0';
    }
}

int sd_recovery_verify(const char *key, char *detail, size_t detail_len)
{
    char path[SD_PATH_MAX];
    char json[1024];
    char hash_hex[SD_HASH_MAX * 2 + 2];
    char normalized[128];
    char payload[sizeof(SD_RECOVERY_PREFIX) - 1 + sizeof(normalized)];
    uint8_t expected[SD_HASH_MAX];
    uint8_t digest[32];

    if (detail != NULL && detail_len > 0) {
        detail[0] = '\0';
    }
    if (sd_read_file(sd_state_path("recovery.verifier", path, sizeof(path)),
                     json, sizeof(json)) < 0) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "no recovery key is configured");
        }
        return 2;
    }
    if (sd_json_string(json, "hash", hash_hex, sizeof(hash_hex)) < 0 ||
        sd_hex_decode(hash_hex, expected, sizeof(expected)) != 32) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the recovery verifier is unreadable");
        }
        return 2;
    }
    sd_normalize_recovery_key(key, normalized, sizeof(normalized));
    if (normalized[0] == '\0') {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "the recovery key is incorrect");
        }
        return 1;
    }
    snprintf(payload, sizeof(payload), "%s%s", SD_RECOVERY_PREFIX, normalized);
    sd_sha256(payload, strlen(payload), digest);
    if (sd_constant_time_eq(digest, expected, 32) == 1) {
        if (detail != NULL && detail_len > 0) {
            snprintf(detail, detail_len, "accepted");
        }
        return SD_OK;
    }
    if (detail != NULL && detail_len > 0) {
        snprintf(detail, detail_len, "the recovery key is incorrect");
    }
    return 1;
}

/* ================================================================== */
/* small parsing helpers used by the configuration reader              */
/* ================================================================== */

static int sd_truth(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    if (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' ||
        value[0] == 't' || value[0] == 'T') {
        return 1;
    }
    return strcasecmp(value, "on") == 0 || strcasecmp(value, "true") == 0 ||
           strcasecmp(value, "yes") == 0;
}

static int sd_role_from_text(const char *value)
{
    if (value == NULL) {
        return SD_ROLE_REGULAR;
    }
    if (strcasecmp(value, "admin") == 0 || strcasecmp(value, "administrator") == 0) {
        return SD_ROLE_ADMIN;
    }
    if (strcasecmp(value, "exempt") == 0) {
        return SD_ROLE_EXEMPT;
    }
    return SD_ROLE_REGULAR;
}

static int sd_parse_hhmm(const char *text)
{
    int hours = 0, minutes = 0;
    if (text == NULL || sscanf(text, "%d:%d", &hours, &minutes) < 2) {
        return -1;
    }
    if (hours < 0 || hours > 24 || minutes < 0 || minutes > 59) {
        return -1;
    }
    return hours * 60 + minutes;
}

static size_t sd_user_index(struct sd_config *cfg, const char *name)
{
    size_t i;
    for (i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].name, name) == 0) {
            return i;
        }
    }
    if (cfg->user_count >= SD_MAX_USERS) {
        return SD_MAX_USERS;
    }
    snprintf(cfg->users[cfg->user_count].name, SD_USER_NAME_MAX, "%s", name);
    cfg->users[cfg->user_count].role = cfg->default_role;
    cfg->users[cfg->user_count].exempt = cfg->default_exempt;
    return cfg->user_count++;
}

static size_t sd_action_index(struct sd_config *cfg, const char *name)
{
    size_t i;
    for (i = 0; i < cfg->action_count; i++) {
        if (strcmp(cfg->actions[i].name, name) == 0) {
            return i;
        }
    }
    if (cfg->action_count >= SD_MAX_ACTIONS) {
        return SD_MAX_ACTIONS;
    }
    snprintf(cfg->actions[cfg->action_count].name, SD_ACTION_NAME_MAX, "%s", name);
    cfg->actions[cfg->action_count].blocked = 0;
    cfg->actions[cfg->action_count].require_master = cfg->default_require;
    return cfg->action_count++;
}

static void sd_days_parse(const char *text, char days[SD_WINDOW_DAYS])
{
    static const char *names[7] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
    const char *cursor;
    int i;

    memset(days, 0, SD_WINDOW_DAYS);
    if (text == NULL) {
        memset(days, 0x7f, 7);
        return;
    }

    /*
     * Split on ',', ';' and ' ' by hand: strtok() must not be used here, the
     * caller iterates over the file with it (see sd_config_parse()).
     */
    cursor = text;
    while (*cursor != '\0') {
        char token[32];
        size_t length = 0;

        while (*cursor == ',' || *cursor == ';' || *cursor == ' ' ||
               *cursor == '\t' || *cursor == '\r') {
            cursor++;
        }
        while (*cursor != '\0' && *cursor != ',' && *cursor != ';' &&
               *cursor != ' ' && *cursor != '\t' && *cursor != '\r') {
            if (length + 1 < sizeof(token)) {
                token[length++] = *cursor;
            }
            cursor++;
        }
        token[length] = '\0';
        if (length == 0) {
            continue;
        }
        if (isdigit((unsigned char)token[0])) {
            int value = atoi(token);
            if (value >= 0 && value <= 6) {
                days[value] = 1;
            } else if (value == 7) {
                days[6] = 1;
            }
            continue;
        }
        for (i = 0; i < 7; i++) {
            if (strncasecmp(token, names[i], 3) == 0) {
                days[i] = 1;
                break;
            }
        }
    }
    if (days[0] == 0 && days[1] == 0 && days[2] == 0 && days[3] == 0 &&
        days[4] == 0 && days[5] == 0 && days[6] == 0) {
        memset(days, 0x7f, 7);
    }
}

/*
 * One pass over the configuration text.  With `globals_only` set the sections
 * are skipped, which is how the global defaults are collected before the per
 * user / per action entries are created: a file may list them in any order and
 * sd_user_index()/sd_action_index() copy the defaults into a new entry at the
 * moment its section header is read.
 */
static void sd_config_parse(struct sd_config *cfg, char *buffer, int globals_only)
{
    char *line;
    int section_kind = -1;         /* 0 = user, 1 = action, 2 = schedule */
    size_t section_index = 0;

    for (line = strtok(buffer, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        char *equals;
        char *key = line;
        char *value;
        while (*key == ' ' || *key == '\t') {
            key++;
        }
        if (*key == '\0' || *key == '#' || *key == ';') {
            continue;
        }
        if (*key == '[') {
            char *close;
            if (globals_only) {
                section_kind = -1;
                continue;
            }
            close = strchr(key, ']');
            if (close == NULL) {
                continue;
            }
            *close = '\0';
            if (strncmp(key + 1, "user:", 5) == 0) {
                section_kind = 0;
                section_index = sd_user_index(cfg, key + 6);
            } else if (strncmp(key + 1, "action:", 7) == 0) {
                section_kind = 1;
                section_index = sd_action_index(cfg, key + 8);
            } else if (strcmp(key + 1, "schedule") == 0) {
                section_kind = 2;
                section_index = 0;
            } else {
                section_kind = -1;
            }
            continue;
        }
        equals = strchr(key, '=');
        if (equals == NULL) {
            continue;
        }
        *equals = '\0';
        value = equals + 1;
        {
            char *end = value + strlen(value);
            while (end > value && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
                *--end = '\0';
            }
        }

        if (section_kind == 0 && section_index < SD_MAX_USERS) {
            if (strcmp(key, "role") == 0) {
                cfg->users[section_index].role = sd_role_from_text(value);
            } else if (strcmp(key, "exempt") == 0) {
                cfg->users[section_index].exempt = sd_truth(value);
            }
            continue;
        }
        if (section_kind == 1 && section_index < SD_MAX_ACTIONS) {
            if (strcmp(key, "blocked") == 0) {
                cfg->actions[section_index].blocked = sd_truth(value);
            } else if (strcmp(key, "require_master") == 0 ||
                       strcmp(key, "bypass") == 0) {
                cfg->actions[section_index].require_master = sd_truth(value);
            }
            continue;
        }
        if (section_kind == 2) {
            if (strcmp(key, "mode") == 0) {
                if (strcmp(value, "enforce-during") == 0 ||
                    strcmp(value, "enforce_during") == 0) {
                    cfg->schedule_mode = SD_SCHEDULE_DURING;
                } else if (strcmp(value, "enforce-outside") == 0 ||
                           strcmp(value, "enforce_outside") == 0) {
                    cfg->schedule_mode = SD_SCHEDULE_OUTSIDE;
                } else {
                    cfg->schedule_mode = SD_SCHEDULE_ALWAYS;
                }
            } else if (strcmp(key, "window") == 0 &&
                       cfg->window_count < SD_MAX_WINDOWS) {
                char buffer2[128];
                char *first, *second, *third;
                struct sd_window *slot = &cfg->windows[cfg->window_count];
                snprintf(buffer2, sizeof(buffer2), "%s", value);
                first = strrchr(buffer2, ',');
                if (first == NULL) {
                    continue;
                }
                *first = '\0';
                third = first + 1;
                second = strrchr(buffer2, ',');
                if (second == NULL) {
                    continue;
                }
                *second = '\0';
                second++;
                slot->start_minute = sd_parse_hhmm(second);
                slot->end_minute = sd_parse_hhmm(third);
                if (slot->start_minute < 0 || slot->end_minute < 0) {
                    continue;
                }
                sd_days_parse(buffer2, slot->days);
                cfg->window_count++;
            }
            continue;
        }

        /* global keys */
        if (strcmp(key, "schema") == 0) {
            cfg->schema = atoi(value);
        } else if (strcmp(key, "enabled") == 0) {
            cfg->enabled = sd_truth(value);
        } else if (strcmp(key, "fail_closed") == 0) {
            cfg->fail_closed = sd_truth(value);
        } else if (strcmp(key, "audit") == 0) {
            cfg->audit_enabled = sd_truth(value);
        } else if (strcmp(key, "max_attempts") == 0) {
            cfg->max_attempts = (uint32_t)atoi(value);
        } else if (strcmp(key, "prompt_timeout") == 0) {
            cfg->prompt_timeout = (uint32_t)atoi(value);
        } else if (strcmp(key, "prompt_text") == 0) {
            snprintf(cfg->prompt_text, sizeof(cfg->prompt_text), "%s", value);
        } else if (strcmp(key, "default_role") == 0) {
            cfg->default_role = sd_role_from_text(value);
        } else if (strcmp(key, "default_exempt") == 0) {
            cfg->default_exempt = sd_truth(value);
        } else if (strcmp(key, "default_require") == 0) {
            cfg->default_require = sd_truth(value);
        } else if (strcmp(key, "verifier") == 0) {
            snprintf(cfg->verifier_path, sizeof(cfg->verifier_path), "%s", value);
        } else if (strcmp(key, "chkpwd") == 0) {
            snprintf(cfg->chkpwd_path, sizeof(cfg->chkpwd_path), "%s", value);
        }
    }
}

int sd_config_load(struct sd_config *cfg, char *err, size_t errlen)
{
    char path[SD_PATH_MAX];
    char buffer[32768];

    memset(cfg, 0, sizeof(*cfg));
    cfg->schema = 1;
    cfg->enabled = 1;
    cfg->fail_closed = 1;
    cfg->max_attempts = 3;
    cfg->prompt_timeout = 120;
    cfg->default_role = SD_ROLE_REGULAR;
    cfg->default_require = 1;
    cfg->audit_enabled = 1;
    cfg->schedule_mode = SD_SCHEDULE_ALWAYS;
    snprintf(cfg->prompt_text, sizeof(cfg->prompt_text), "Please Enter the Master Password:");
    sd_state_path("master.verifier", cfg->verifier_path, sizeof(cfg->verifier_path));
    snprintf(cfg->chkpwd_path, sizeof(cfg->chkpwd_path), "%s", "/usr/lib/sudaeon/sudaeon-chkpwd");
    snprintf(cfg->audit_path, sizeof(cfg->audit_path), "%s", SD_AUDIT_FILE);
    cfg->marker_present = sd_file_exists(sd_state_path("installed.json", path,
                                                        sizeof(path)));

    if (sd_read_file(sd_state_path("enforcement.conf", path, sizeof(path)),
                     buffer, sizeof(buffer)) < 0) {
        if (err != NULL && errlen > 0) {
            snprintf(err, errlen, "the enforcement configuration is missing");
        }
        return SD_ERR_IO;
    }
    /* pass 1: the global defaults; pass 2: everything, now with them known */
    sd_config_parse(cfg, buffer, 1);
    if (sd_read_file(sd_state_path("enforcement.conf", path, sizeof(path)),
                     buffer, sizeof(buffer)) < 0) {
        if (err != NULL && errlen > 0) {
            snprintf(err, errlen, "the enforcement configuration is missing");
        }
        return SD_ERR_IO;
    }
    sd_config_parse(cfg, buffer, 0);

    cfg->loaded = 1;
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    return SD_OK;
}

const struct sd_action_entry *sd_config_action(const struct sd_config *cfg,
                                               const char *name)
{
    static struct sd_action_entry fallback;
    size_t i;

    for (i = 0; i < cfg->action_count; i++) {
        if (strcmp(cfg->actions[i].name, name) == 0) {
            return &cfg->actions[i];
        }
    }
    memset(&fallback, 0, sizeof(fallback));
    snprintf(fallback.name, sizeof(fallback.name), "%s", name);
    fallback.blocked = 0;
    fallback.require_master = cfg->default_require;
    return &fallback;
}

int sd_config_user_exempt(const struct sd_config *cfg, const char *user)
{
    size_t i;
    for (i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].name, user) == 0) {
            return cfg->users[i].exempt;
        }
    }
    for (i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].name, "*") == 0) {
            return cfg->users[i].exempt;
        }
    }
    return cfg->default_exempt;
}

int sd_config_user_role(const struct sd_config *cfg, const char *user)
{
    size_t i;
    for (i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].name, user) == 0) {
            return cfg->users[i].role;
        }
    }
    for (i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].name, "*") == 0) {
            return cfg->users[i].role;
        }
    }
    return cfg->default_role;
}

/*
 * Window matching, identical to sudaeon.schedule.in_active_window():
 * a window covers [start, end) on its days, with the part after midnight
 * belonging to the *following* day, so Monday 21:00-07:00 also covers
 * Tuesday 00:00-07:00.
 */
static int sd_window_contains(const struct sd_window *window, int weekday,
                              int minute)
{
    int previous = (weekday + 6) % 7;

    if (window->start_minute <= window->end_minute) {
        return window->days[weekday] && minute >= window->start_minute &&
               minute < window->end_minute;
    }
    if (window->days[weekday] && minute >= window->start_minute) {
        return 1;
    }
    return window->days[previous] && minute < window->end_minute;
}

static int sd_parse_iso_local(const char *text, time_t *out)
{
    struct tm tm;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    const char *position;
    long offset = 0;
    int sign = 1;

    memset(&tm, 0, sizeof(tm));
    if (text == NULL || sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d",
                               &year, &month, &day, &hour, &minute, &second) < 5) {
        return -1;
    }
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;

    position = strchr(text, 'Z');
    if (position == NULL && strlen(text) > 19) {
        position = strchr(text + 19, '+');
        if (position == NULL) {
            position = strchr(text + 19, '-');
        }
    }
    if (position != NULL) {
        if (*position == '-') {
            sign = -1;
        }
        if (*position != 'Z') {
            int oh = 0, om = 0;
            if (sscanf(position + 1, "%2d:%2d", &oh, &om) >= 1) {
                offset = sign * (oh * 3600L + (om > 0 ? om * 60L : 0L));
            }
        }
        *out = timegm(&tm) - offset;
    } else {
        *out = mktime(&tm);
    }
    return 0;
}

int sd_schedule_active(const struct sd_config *cfg, const char *now_iso,
                       const char *timezone)
{
    struct tm tm;
    time_t stamp;
    size_t i;
    int weekday, minute;

    if (cfg->schedule_mode == SD_SCHEDULE_ALWAYS || cfg->window_count == 0) {
        return 1;
    }
    if (now_iso == NULL) {
        stamp = time(NULL);
    } else if (sd_parse_iso_local(now_iso, &stamp) != 0) {
        stamp = time(NULL);
    }
    if (timezone != NULL && timezone[0] != '\0') {
        setenv("TZ", timezone, 1);
        tzset();
    }
    if (localtime_r(&stamp, &tm) == NULL) {
        return cfg->schedule_mode == SD_SCHEDULE_OUTSIDE ? 0 : 1;
    }
    weekday = (tm.tm_wday + 6) % 7;         /* 0 = Monday */
    minute = tm.tm_hour * 60 + tm.tm_min;

    for (i = 0; i < cfg->window_count; i++) {
        if (sd_window_contains(&cfg->windows[i], weekday, minute)) {
            return cfg->schedule_mode == SD_SCHEDULE_DURING ? 1 : 0;
        }
    }
    return cfg->schedule_mode == SD_SCHEDULE_DURING ? 0 : 1;
}
