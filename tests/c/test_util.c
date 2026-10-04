/*
 * test_util.c - checks for src/sudaeon/cutil.c
 *
 * Everything here is checked against published test vectors:
 *   - SHA-256 / HMAC-SHA-256: NIST FIPS 180-4 and RFC 4231
 *   - PBKDF2-HMAC-SHA-256, Salsa20/8, BlockMix, ROMix, scrypt: RFC 7914
 *
 * Build and run with `make -C tests/c test-util`.
 */

#define _GNU_SOURCE
#include "../../src/sudaeon/cutil.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int checks_run = 0;
static int checks_failed = 0;
static char temp_dir[256];

#define CHECK(condition, ...)                                                  \
    do {                                                                       \
        checks_run++;                                                          \
        if (!(condition)) {                                                    \
            checks_failed++;                                                   \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                      \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

static void hex_decode(const char *hex, uint8_t *out, size_t outlen)
{
    size_t i;
    for (i = 0; i < outlen; i++) {
        unsigned int value = 0;
        sscanf(hex + i * 2, "%2x", &value);
        out[i] = (uint8_t)value;
    }
}

static const char *hex_encode(const uint8_t *data, size_t len)
{
    static char buffer[1024];
    size_t i;
    for (i = 0; i < len && i * 2 + 2 < sizeof(buffer); i++) {
        sprintf(buffer + i * 2, "%02x", data[i]);
    }
    if (len * 2 < sizeof(buffer)) {
        buffer[len * 2] = '\0';
    }
    return buffer;
}

static char *hex_of(const uint8_t *data, size_t len)
{
    static char buffer[4096];
    size_t i;
    for (i = 0; i < len; i++) {
        sprintf(buffer + i * 2, "%02x", data[i]);
    }
    buffer[len * 2] = '\0';
    return buffer;
}

/* ------------------------------------------------------------------ */

static void test_sha256(void)
{
    uint8_t digest[32];
    char hex[65];
    int i;
    uint8_t big[1000];

    sd_sha256("", 0, digest);
    CHECK(strcmp(hex_encode(digest, 32),
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "SHA-256 of the empty string");

    sd_sha256("abc", 3, digest);
    CHECK(strcmp(hex_encode(digest, 32),
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "SHA-256(\"abc\")");

    sd_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
    CHECK(strcmp(hex_encode(digest, 32),
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
          "SHA-256 of the 56 byte NIST message");

    for (i = 0; i < 1000; i++) {
        big[i] = 'a';
    }
    sd_sha256(big, 1000, digest);
    CHECK(strcmp(hex_encode(digest, 32),
                 "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") == 0,
          "SHA-256 of 1000 'a'");

    sd_sha256_hex("abc", 3, hex);
    CHECK(strncmp(hex, "ba7816bf", 8) == 0, "sd_sha256_hex output");
}

static void test_hmac(void)
{
    /* RFC 4231 test case 1-3 */
    uint8_t key[20];
    uint8_t out[32];

    memset(key, 0x0b, 20);
    sd_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
    CHECK(strcmp(hex_encode(out, 32),
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0,
          "RFC 4231 case 1");

    sd_hmac_sha256((const uint8_t *)"Jefe", 4,
                   (const uint8_t *)"what do ya want for nothing?", 28, out);
    CHECK(strcmp(hex_encode(out, 32),
                 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0,
          "RFC 4231 case 2");

    memset(key, 0xaa, 20);
    {
        uint8_t fifty[50];
        memset(fifty, 0xdd, sizeof(fifty));
        sd_hmac_sha256(key, 20, fifty, sizeof(fifty), out);
    }
    CHECK(strcmp(hex_encode(out, 32),
                 "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe") == 0,
          "RFC 4231 case 3");
}

static void test_pbkdf2(void)
{
    uint8_t out[64];

    /* RFC 7914 section 11 */
    CHECK(sd_pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6,
                                (const uint8_t *)"salt", 4, 1, out, 64) == SD_OK,
          "pbkdf2 returns SD_OK");
    CHECK(strcmp(hex_of(out, 64),
                 "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                 "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783") == 0,
          "PBKDF2-HMAC-SHA-256 c=1");

    CHECK(sd_pbkdf2_hmac_sha256((const uint8_t *)"Password", 8,
                                (const uint8_t *)"NaCl", 4, 80000, out, 64) == SD_OK,
          "pbkdf2 80000 rounds returns SD_OK");
    CHECK(strcmp(hex_of(out, 64),
                 "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                 "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d") == 0,
          "PBKDF2-HMAC-SHA-256 c=80000");
}

static void test_salsa20_8(void)
{
    /* RFC 7914 section 8 */
    uint8_t block[64];
    hex_decode("7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d"
               "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e",
               block, 64);
    sd_salsa20_8(block);
    CHECK(strcmp(hex_of(block, 64),
                 "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29"
                 "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81") == 0,
          "Salsa20/8 core");
}

static void test_blockmix(void)
{
    /* RFC 7914 section 9: r = 1, B[0] and B[1] -> B'[0] and B'[1] */
    uint8_t b[128];
    uint8_t y[128];
    uint8_t scratch[256];
    hex_decode("f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"
               "89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7"
               "894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b0"
               "67d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89",
               b, 128);
    sd_blockmix((const uint32_t *)b, (uint32_t *)y, (uint32_t *)scratch, 1);
    CHECK(strcmp(hex_of(y, 128),
                 "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29"
                 "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81"
                 "20edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b7"
                 "7d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425") == 0,
          "scryptBlockMix r=1");
}

static void test_romix(void)
{
    /* RFC 7914 section 10: r = 1, N = 16 */
    uint8_t b[128];
    uint32_t words[32];
    int i;
    hex_decode("f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"
               "89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7"
               "894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b0"
               "67d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89",
               b, 128);
    for (i = 0; i < 32; i++) {
        words[i] = (uint32_t)b[i * 4] | ((uint32_t)b[i * 4 + 1] << 8) |
                   ((uint32_t)b[i * 4 + 2] << 16) | ((uint32_t)b[i * 4 + 3] << 24);
    }
    CHECK(sd_romix(words, 16, 1) == SD_OK, "romix returns SD_OK");
    for (i = 0; i < 32; i++) {
        b[i * 4] = (uint8_t)(words[i] & 0xff);
        b[i * 4 + 1] = (uint8_t)((words[i] >> 8) & 0xff);
        b[i * 4 + 2] = (uint8_t)((words[i] >> 16) & 0xff);
        b[i * 4 + 3] = (uint8_t)((words[i] >> 24) & 0xff);
    }

    /* The reference value, whitespace free. */
    CHECK(strcmp(hex_of(b, 128),
                 "79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46"
                 "d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71"
                 "ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4"
                 "ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e"
                ) == 0,
          "scryptROMix r=1 N=16");
}

static void test_scrypt(void)
{
    uint8_t out[64];

    /* RFC 7914 section 12, vector 1 */
    CHECK(sd_scrypt((const uint8_t *)"", 0, (const uint8_t *)"", 0, 16, 1, 1, out, 64) == SD_OK,
          "scrypt vector 1 returns SD_OK");
    CHECK(strcmp(hex_of(out, 64),
                 "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                 "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906") == 0,
          "scrypt(P=\"\", S=\"\", N=16, r=1, p=1)");

    /* vector 2 */
    CHECK(sd_scrypt((const uint8_t *)"password", 8, (const uint8_t *)"NaCl", 4,
                    1024, 8, 16, out, 64) == SD_OK,
          "scrypt vector 2 returns SD_OK");
    CHECK(strcmp(hex_of(out, 64),
                 "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                 "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640") == 0,
          "scrypt(P=\"password\", S=\"NaCl\", N=1024, r=8, p=16)");

    /* vector 3 */
    CHECK(sd_scrypt((const uint8_t *)"pleaseletmein", 13,
                    (const uint8_t *)"SodiumChloride", 14, 16384, 8, 1, out, 64) == SD_OK,
          "scrypt vector 3 returns SD_OK");
    CHECK(strcmp(hex_of(out, 64),
                 "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                 "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887") == 0,
          "scrypt(P=\"pleaseletmein\", S=\"SodiumChloride\", N=16384, r=8, p=1)");
}

static void test_constant_time(void)
{
    CHECK(sd_constant_time_eq("abcdef", "abcdef", 6) == 1, "equal buffers");
    CHECK(sd_constant_time_eq("abcdef", "abcdeg", 6) == 0, "different buffers");
}

/* ------------------------------------------------------------------ */
/* rate limiting                                                       */
/* ------------------------------------------------------------------ */

static void test_lockout(void)
{
    uint32_t remaining = 0, fails = 0, seconds = 0;
    int locked = 0;
    char path[256];

    snprintf(path, sizeof(path), "%s/lockout.json", temp_dir);
    unlink(path);

    CHECK(sd_lockout_locked(&remaining) == 0, "no lock at the start");
    sd_lockout_fail(3, &locked, &seconds);
    CHECK(locked == 0, "one failure does not lock");
    sd_lockout_fail(3, &locked, &seconds);
    CHECK(locked == 0, "two failures do not lock");
    sd_lockout_fail(3, &locked, &seconds);
    CHECK(locked == 1, "the third failure locks");
    CHECK(seconds == 30, "the first lock lasts 30 seconds");
    CHECK(sd_lockout_locked(&remaining) == 1, "the lock is reported");
    CHECK(remaining > 0 && remaining <= 30, "remaining time is sane");

    sd_lockout_status(&fails, &remaining);
    CHECK(fails == 3, "three failures recorded");

    /* Further failures double the wait. */
    sd_lockout_fail(3, &locked, &seconds);
    CHECK(seconds == 60, "the second lock lasts 60 seconds");
    sd_lockout_fail(3, &locked, &seconds);
    sd_lockout_fail(3, &locked, &seconds);
    sd_lockout_fail(3, &locked, &seconds);
    CHECK(seconds == 480, "the wait doubles every time");

    sd_lockout_clear();
    sd_lockout_status(&fails, &remaining);
    CHECK(fails == 0 && remaining == 0, "clearing resets the state");
    CHECK(sd_lockout_locked(&remaining) == 0, "no lock after clearing");
}

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */

static void write_sample_config(void)
{
    char path[256];
    FILE *handle;
    snprintf(path, sizeof(path), "%s/enforcement.conf", temp_dir);
    handle = fopen(path, "w");
    if (handle == NULL) {
        printf("  cannot write %s\n", path);
        exit(2);
    }
    fprintf(handle,
            "# Sudaeon enforcement configuration (test)\n"
            "schema=1\n"
            "enabled=1\n"
            "fail_closed=1\n"
            "max_attempts=3\n"
            "prompt_text=Please Enter the Master Password:\n"
            "audit=1\n"
            "default_role=regular\n"
            "[user:alice]\n"
            "role=admin\n"
            "exempt=0\n"
            "[user:bob]\n"
            "role=exempt\n"
            "exempt=1\n"
            "[user:*]\n"
            "role=regular\n"
            "exempt=0\n"
            "[action:sudo]\n"
            "blocked=1\n"
            "require_master=1\n"
            "[action:su]\n"
            "blocked=1\n"
            "require_master=0\n"
            "[action:root_login]\n"
            "blocked=1\n"
            "require_master=0\n"
            "[schedule]\n"
            "mode=enforce-during\n"
            "window=Mon,Tue,Wed,Thu,Fri,21:00,07:00\n");
    fclose(handle);
}

static void test_config(void)
{
    struct sd_config cfg;
    char err[256];

    write_sample_config();
    CHECK(sd_config_load(&cfg, err, sizeof(err)) == SD_OK, "config loads");
    CHECK(err[0] == '\0', "no error message on success");
    CHECK(cfg.enabled == 1, "enabled flag");
    CHECK(cfg.max_attempts == 3, "max attempts");
    CHECK(strcmp(cfg.prompt_text, "Please Enter the Master Password:") == 0, "prompt text");
    CHECK(cfg.user_count == 3, "three user sections");

    CHECK(sd_config_user_role(&cfg, "alice") == SD_ROLE_ADMIN, "alice is an administrator");
    CHECK(sd_config_user_role(&cfg, "bob") == SD_ROLE_EXEMPT, "bob is exempt");
    CHECK(sd_config_user_role(&cfg, "carol") == SD_ROLE_REGULAR, "carol falls back");
    CHECK(sd_config_user_exempt(&cfg, "bob") == 1, "bob is exempt flag");
    CHECK(sd_config_user_exempt(&cfg, "alice") == 0, "alice is not exempt");

    CHECK(sd_config_action(&cfg, "sudo")->blocked == 1, "sudo is blocked");
    CHECK(sd_config_action(&cfg, "sudo")->require_master == 1, "sudo can be unlocked");
    CHECK(sd_config_action(&cfg, "su")->blocked == 1, "su is blocked");
    CHECK(sd_config_action(&cfg, "su")->require_master == 0, "su cannot be unlocked");
    CHECK(sd_config_action(&cfg, "reboot")->blocked == 0, "unknown actions are not blocked");

    CHECK(cfg.schedule_mode == SD_SCHEDULE_DURING, "schedule mode parsed");
    CHECK(cfg.window_count == 1, "one window parsed");
    CHECK(cfg.windows[0].start_minute == 21 * 60, "window start");
    CHECK(cfg.windows[0].end_minute == 7 * 60, "window end");
    CHECK(cfg.windows[0].days[0] == 1, "Monday is in the window");
    CHECK(cfg.windows[0].days[6] == 0, "Sunday is not in the window");

    /* Wednesday 22:00 local time -> inside */
    CHECK(sd_schedule_active(&cfg, "2026-10-07T22:00:00", "UTC") == 1,
          "Wednesday 22:00 is inside the window");
    /* Wednesday 12:00 -> outside */
    CHECK(sd_schedule_active(&cfg, "2026-10-07T12:00:00", "UTC") == 0,
          "Wednesday 12:00 is outside the window");
    /* Thursday 02:00 -> inside (spill over from Wednesday) */
    CHECK(sd_schedule_active(&cfg, "2026-10-08T02:00:00", "UTC") == 1,
          "Thursday 02:00 is inside the window");
    /* Saturday 02:00 -> inside: Friday evening spills into Saturday morning */
    CHECK(sd_schedule_active(&cfg, "2026-10-10T02:00:00", "UTC") == 1,
          "Saturday 02:00 is inside the window (Friday night)");
    /* Saturday 20:00 -> outside, Saturday 22:00 -> outside */
    CHECK(sd_schedule_active(&cfg, "2026-10-10T20:00:00", "UTC") == 0,
          "Saturday 20:00 is outside the window");
    /* Monday morning belongs to Sunday night, which is not scheduled ... */
    CHECK(sd_schedule_active(&cfg, "2026-10-05T06:59:00", "UTC") == 0,
          "Monday 06:59 is outside the window (Sunday night is not scheduled)");
    /* ... but Monday evening is. */
    CHECK(sd_schedule_active(&cfg, "2026-10-05T21:30:00", "UTC") == 1,
          "Monday 21:30 is inside the window");
    CHECK(sd_schedule_active(&cfg, "2026-10-06T02:00:00", "UTC") == 1,
          "Tuesday 02:00 is inside the window (Monday night)");
    CHECK(sd_schedule_active(&cfg, "2026-10-06T07:00:00", "UTC") == 0,
          "Tuesday 07:00 is outside the window");
}

/* ------------------------------------------------------------------ */
/* audit log                                                           */
/* ------------------------------------------------------------------ */

static void test_audit(void)
{
    char path[256];
    char line[1024];
    FILE *handle;
    snprintf(path, sizeof(path), "%s/audit.log", temp_dir);
    unlink(path);

    sd_audit("sudo", "deny", "pam", "alice tried to run sudo");
    sd_audit("sudo", "master-ok", "chkpwd", NULL);

    handle = fopen(path, "r");
    CHECK(handle != NULL, "the audit log was written");
    if (handle == NULL) {
        return;
    }
    CHECK(fgets(line, sizeof(line), handle) != NULL, "first audit line readable");
    CHECK(strstr(line, "\"action\":\"sudo\"") != NULL, "action recorded");
    CHECK(strstr(line, "\"result\":\"deny\"") != NULL, "result recorded");
    CHECK(strstr(line, "\"source\":\"pam\"") != NULL, "source recorded");
    CHECK(strstr(line, "\"detail\":\"alice tried to run sudo\"") != NULL, "detail recorded");
    CHECK(strstr(line, "\"uid\":") != NULL, "uid recorded");
    CHECK(strstr(line, "\"pid\":") != NULL, "pid recorded");
    CHECK(strstr(line, "\"ts\":\"20") != NULL, "timestamp recorded");
    CHECK(fgets(line, sizeof(line), handle) != NULL, "second audit line readable");
    CHECK(strstr(line, "\"detail\"") == NULL, "no empty detail field");
    fclose(handle);
}

static void test_master_verifier(void)
{
    static const char prefix[] = "SUDAEON-VERIFIER-V1";
    char path[256];
    char detail[256];
    char salt_hex[33];
    char hash_hex[65];
    uint8_t salt[16];
    uint8_t key[32];
    uint8_t payload[sizeof(prefix) - 1 + 32];
    uint8_t digest[32];
    FILE *handle;
    int rc;

    for (rc = 0; rc < 16; rc++) {
        salt[rc] = (uint8_t)(0x10 + rc);
        sprintf(salt_hex + rc * 2, "%02x", salt[rc]);
    }
    salt_hex[32] = '\0';

    /* Build the verifier exactly the way the Python side does. */
    CHECK(sd_scrypt((const uint8_t *)"correct horse battery staple", 28, salt, 16,
                    16, 1, 1, key, 32) == SD_OK, "scrypt for the verifier");
    memcpy(payload, prefix, sizeof(prefix) - 1);
    memcpy(payload + sizeof(prefix) - 1, key, 32);
    sd_sha256(payload, sizeof(prefix) - 1 + 32, digest);
    for (rc = 0; rc < 32; rc++) {
        sprintf(hash_hex + rc * 2, "%02x", digest[rc]);
    }
    hash_hex[64] = '\0';

    snprintf(path, sizeof(path), "%s/master.verifier", temp_dir);
    handle = fopen(path, "w");
    CHECK(handle != NULL, "verifier file created");
    if (handle == NULL) {
        return;
    }
    fprintf(handle, "{\"version\":1,\"kdf\":\"scrypt\",\"n\":16,\"r\":1,\"p\":1,"
                    "\"dklen\":32,\"salt\":\"%s\",\"hash\":\"%s\"}\n",
            salt_hex, hash_hex);
    fclose(handle);

    rc = sd_master_verify("correct horse battery staple", detail, sizeof(detail));
    CHECK(rc == SD_OK, "the correct password is accepted (rc=%d)", rc);
    rc = sd_master_verify("correct horse battery stapl", detail, sizeof(detail));
    CHECK(rc == 1, "a wrong password is refused (rc=%d)", rc);
    CHECK(strstr(detail, "incorrect") != NULL, "the message mentions an incorrect password");
    rc = sd_master_verify("", detail, sizeof(detail));
    CHECK(rc == 1, "an empty password is refused");
    unlink(path);
    rc = sd_master_verify("correct horse battery staple", detail, sizeof(detail));
    CHECK(rc == 2, "a missing verifier is an error, not a match");
}

/* ------------------------------------------------------------------ */
/* the file the Python renderer writes                                  */
/*                                                                      */
/* tests/test_config.py renders tests/fixtures/enforcement.conf and      */
/* compares it byte for byte with config.render_enforcement_conf(); the   */
/* same file is loaded here, so a format change on either side fails.     */
/* ------------------------------------------------------------------ */

static const char *python_fixture_path(void)
{
    static const char *candidates[] = {
        "tests/fixtures/enforcement.conf",
        "../fixtures/enforcement.conf",
        "../../tests/fixtures/enforcement.conf",
        "../../../tests/fixtures/enforcement.conf",
        NULL,
    };
    int i;

    for (i = 0; candidates[i] != NULL; i++) {
        if (sd_file_exists(candidates[i])) {
            return candidates[i];
        }
    }
    return NULL;
}

static int copy_file(const char *source, const char *target)
{
    FILE *in = fopen(source, "r");
    FILE *out;
    char buffer[4096];
    size_t got;

    if (in == NULL) {
        return 0;
    }
    out = fopen(target, "w");
    if (out == NULL) {
        fclose(in);
        return 0;
    }
    while ((got = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        fwrite(buffer, 1, got, out);
    }
    fclose(in);
    fclose(out);
    return 1;
}

static void test_python_fixture(void)
{
    const char *source = python_fixture_path();
    char target[300];
    struct sd_config cfg;
    char err[256];
    const struct sd_action_entry *entry;

    if (source == NULL) {
        printf("  (skipped: tests/fixtures/enforcement.conf was not found)\n");
        return;
    }
    snprintf(target, sizeof(target), "%s/enforcement.conf", temp_dir);
    if (!copy_file(source, target)) {
        CHECK(0, "cannot copy %s", source);
        return;
    }

    CHECK(sd_config_load(&cfg, err, sizeof(err)) == SD_OK,
          "the Python rendered file parses: %s", err);
    CHECK(cfg.schema == 1, "schema from the fixture (got %d)", cfg.schema);
    CHECK(cfg.enabled == 1, "enabled from the fixture");
    CHECK(cfg.fail_closed == 1, "fail_closed from the fixture");
    CHECK(cfg.audit_enabled == 1, "audit from the fixture");
    CHECK(cfg.max_attempts == 4, "max_attempts from the fixture (got %u)",
          cfg.max_attempts);
    CHECK(cfg.prompt_timeout == 90, "prompt_timeout from the fixture (got %u)",
          cfg.prompt_timeout);
    CHECK(strcmp(cfg.prompt_text, "Please Enter the Master Password:") == 0,
          "prompt_text from the fixture (got '%s')", cfg.prompt_text);

    CHECK(cfg.schedule_mode == SD_SCHEDULE_DURING, "schedule mode from the fixture");
    CHECK(cfg.window_count == 2, "two windows from the fixture (got %u)",
          (unsigned)cfg.window_count);
    if (cfg.window_count == 2) {
        CHECK(cfg.windows[0].start_minute == 21 * 60, "Monday window starts at 21:00");
        CHECK(cfg.windows[0].end_minute == 7 * 60, "Monday window ends at 07:00");
        CHECK(cfg.windows[0].days[0] && cfg.windows[0].days[4], "Monday to Friday");
        CHECK(!cfg.windows[0].days[5] && !cfg.windows[0].days[6], "no weekend days");
        CHECK(cfg.windows[1].start_minute == 9 * 60, "weekend window starts at 09:00");
        CHECK(cfg.windows[1].days[5] && cfg.windows[1].days[6], "weekend days");
    }

    entry = sd_config_action(&cfg, "sudo");
    CHECK(entry->blocked == 1, "sudo is blocked in the fixture");
    CHECK(entry->require_master == 1, "sudo may be unlocked with the master password");
    entry = sd_config_action(&cfg, "root_login");
    CHECK(entry->blocked == 1, "root_login is blocked in the fixture");
    CHECK(entry->require_master == 0, "root_login cannot be unlocked");
    entry = sd_config_action(&cfg, "poweroff");
    CHECK(entry->blocked == 0, "poweroff is allowed in the fixture");
    entry = sd_config_action(&cfg, "not_listed_anywhere");
    CHECK(entry->blocked == 0 && entry->require_master == 1,
          "an unknown action fails closed");

    CHECK(sd_config_user_role(&cfg, "alice") == SD_ROLE_ADMIN, "alice is an admin");
    CHECK(sd_config_user_role(&cfg, "carol") == SD_ROLE_REGULAR, "carol is a user");
    CHECK(sd_config_user_role(&cfg, "dave") == SD_ROLE_REGULAR,
          "dave falls back to the default role");
    CHECK(sd_config_user_exempt(&cfg, "bob") == 1, "bob is exempt");
    CHECK(sd_config_user_exempt(&cfg, "alice") == 0, "alice is not exempt");
    CHECK(sd_config_user_exempt(&cfg, "dave") == 0, "dave is not exempt");

    CHECK(sd_schedule_active(&cfg, "2026-10-05T23:00:00", NULL) == 1,
          "Monday 23:00 is inside the window");
    CHECK(sd_schedule_active(&cfg, "2026-10-06T02:00:00", NULL) == 1,
          "Tuesday 02:00 belongs to Monday's window");
    CHECK(sd_schedule_active(&cfg, "2026-10-05T12:00:00", NULL) == 0,
          "Monday noon is outside the window");
    CHECK(sd_schedule_active(&cfg, "2026-10-10T10:00:00", NULL) == 1,
          "Saturday 10:00 is inside the weekend window");
}


int main(void)
{
    char template[] = "/tmp/sudaeon-test-XXXXXX";

    if (mkdtemp(template) == NULL) {
        printf("cannot create a temporary directory\n");
        return 2;
    }
    snprintf(temp_dir, sizeof(temp_dir), "%s", template);
    setenv("SUDAEON_STATE_DIR", temp_dir, 1);
    {
        char audit_path[300];
        snprintf(audit_path, sizeof(audit_path), "%s/audit.log", temp_dir);
        setenv("SUDAEON_AUDIT_LOG", audit_path, 1);
    }
    if (geteuid() == 0) {
        printf("running as root: the state directory override is ignored, "
               "skipping the file based tests\n");
    }

    printf("SHA-256\n");
    test_sha256();
    printf("HMAC-SHA-256\n");
    test_hmac();
    printf("PBKDF2-HMAC-SHA-256\n");
    test_pbkdf2();
    printf("Salsa20/8 core\n");
    test_salsa20_8();
    printf("scryptBlockMix\n");
    test_blockmix();
    printf("scryptROMix\n");
    test_romix();
    printf("scrypt\n");
    test_scrypt();
    printf("constant time comparison\n");
    test_constant_time();
    if (geteuid() != 0) {
        printf("rate limiting\n");
        test_lockout();
        printf("policy file\n");
        test_config();
        printf("policy file rendered by Python\n");
        test_python_fixture();
        printf("audit log\n");
        test_audit();
        printf("master verifier\n");
        test_master_verifier();
    }

    printf("\n%d checks, %d failures\n", checks_run, checks_failed);
    return checks_failed == 0 ? 0 : 1;
}
