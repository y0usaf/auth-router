#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void sb_init(sb_t *sb) {
    sb->cap = 64;
    sb->len = 0;
    sb->data = malloc(sb->cap);
    if (sb->data) sb->data[0] = '\0';
}

void sb_free(sb_t *sb) {
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static void sb_grow(sb_t *sb, size_t need) {
    if (sb->len + need + 1 <= sb->cap) return;
    size_t ncap = sb->cap ? sb->cap * 2 : 64;
    while (ncap < sb->len + need + 1) ncap *= 2;
    char *p = realloc(sb->data, ncap);
    if (!p) abort();
    sb->data = p;
    sb->cap = ncap;
}

void sb_putc(sb_t *sb, char c) {
    sb_grow(sb, 1);
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

void sb_putn(sb_t *sb, const char *s, size_t n) {
    if (!n) return;
    sb_grow(sb, n);
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

void sb_puts(sb_t *sb, const char *s) {
    if (s) sb_putn(sb, s, strlen(s));
}

void sb_printf(sb_t *sb, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        sb_grow(sb, (size_t)n);
        vsnprintf(sb->data + sb->len, (size_t)n + 1, fmt, ap2);
        sb->len += (size_t)n;
    }
    va_end(ap2);
}

int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

void sleep_ms(int64_t ms) {
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t k256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_block(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k256[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void sha256_bytes(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t st[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    size_t i = 0;
    while (i + 64 <= len) {
        sha256_block(st, data + i);
        i += 64;
    }
    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    size_t rem = len - i;
    if (rem) memcpy(tail, data + i, rem);
    tail[rem] = 0x80;
    size_t total = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) {
        tail[total - 1 - j] = (uint8_t)(bits >> (j * 8));
    }
    sha256_block(st, tail);
    if (total == 128) sha256_block(st, tail + 64);
    for (int j = 0; j < 8; j++) {
        out[j * 4] = (uint8_t)(st[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(st[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(st[j] >> 8);
        out[j * 4 + 3] = (uint8_t)(st[j]);
    }
}

void sha256_hex(const char *s, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t dig[32];
    sha256_bytes((const uint8_t *)s, strlen(s), dig);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hex[dig[i] >> 4];
        out[i * 2 + 1] = hex[dig[i] & 0xf];
    }
    out[64] = '\0';
}

void base64url_encode(const uint8_t *in, size_t len, char *out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)in[i + 2];
        out[j++] = tbl[(v >> 18) & 0x3f];
        out[j++] = tbl[(v >> 12) & 0x3f];
        if (i + 1 < len) out[j++] = tbl[(v >> 6) & 0x3f];
        if (i + 2 < len) out[j++] = tbl[v & 0x3f];
    }
    out[j] = '\0';
}

bool random_bytes(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, out + got, len - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            close(fd);
            return false;
        }
        got += (size_t)r;
    }
    close(fd);
    return true;
}

void random_b64url(size_t nbytes, char *out) {
    uint8_t buf[64];
    if (nbytes > sizeof(buf)) nbytes = sizeof(buf);
    if (!random_bytes(buf, nbytes)) abort();
    base64url_encode(buf, nbytes, out);
}

void url_encode(const char *s, sb_t *out) {
    static const char hex[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            sb_putc(out, (char)c);
        } else {
            sb_putc(out, '%');
            sb_putc(out, hex[c >> 4]);
            sb_putc(out, hex[c & 0xf]);
        }
    }
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void url_decode(const char *s, sb_t *out) {
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '+') {
            sb_putc(out, ' ');
        } else if (s[i] == '%' && s[i + 1] && s[i + 2]) {
            int hi = hex_val(s[i + 1]);
            int lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                sb_putc(out, (char)((hi << 4) | lo));
                i += 2;
            } else {
                sb_putc(out, s[i]);
            }
        } else {
            sb_putc(out, s[i]);
        }
    }
}

char *str_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    return s;
}

void str_lower_copy(const char *s, char *out, size_t n) {
    size_t i = 0;
    for (; s[i] && i + 1 < n; i++) out[i] = (char)tolower((unsigned char)s[i]);
    out[i] = '\0';
}

bool str_to_i64(const char *s, int64_t *out) {
    if (!s || !*s) return false;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return false;
    *out = (int64_t)v;
    return true;
}

static int64_t days_from_civil(int64_t y, int64_t m, int64_t d) {
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

bool parse_iso8601_ms(const char *s, int64_t *out) {
    size_t len = strlen(s);
    if (len < 20 || s[10] != 'T' || s[len - 1] != 'Z') return false;
    char b[8];
    int64_t vals[6];
    int pos[6] = {0, 5, 8, 11, 14, 17};
    int wid[6] = {4, 2, 2, 2, 2, 2};
    for (int i = 0; i < 6; i++) {
        memcpy(b, s + pos[i], (size_t)wid[i]);
        b[wid[i]] = '\0';
        if (!str_to_i64(b, &vals[i])) return false;
    }
    int64_t days = days_from_civil(vals[0], vals[1], vals[2]);
    int64_t secs = days * 86400 + vals[3] * 3600 + vals[4] * 60 + vals[5];
    *out = secs * 1000;
    return true;
}

bool str_contains_ci(const char *hay, const char *needle) {
    if (!*needle) return true;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nlen) return true;
    }
    return false;
}

static char g_state_dir_override[1024];

void state_dir_set_override(const char *dir) {
    if (!dir || !*dir) {
        g_state_dir_override[0] = '\0';
        return;
    }
    snprintf(g_state_dir_override, sizeof(g_state_dir_override), "%s", dir);
    str_trim(g_state_dir_override);
}

bool parse_duration_ms(const char *s, int64_t *out) {
    if (!s || !*s || !out) return false;
    while (*s == ' ' || *s == '\t' || *s == '~') s++;
    if (!*s) return false;
    int64_t plain = 0;
    if (str_to_i64(s, &plain) && plain >= 0) {
        *out = plain;
        return true;
    }
    double total = 0.0;
    bool any = false;
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        char *end = NULL;
        double val = strtod(p, &end);
        if (end == p || val < 0.0) return false;
        p = end;
        while (*p == ' ' || *p == '\t') p++;
        char unit[16];
        size_t ulen = 0;
        while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) {
            if (ulen + 1 < sizeof(unit)) {
                char c = *p;
                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                unit[ulen++] = c;
            }
            p++;
        }
        unit[ulen] = '\0';
        if (ulen == 0) return false;
        double mult = 0.0;
        if (strcmp(unit, "ms") == 0) mult = 1.0;
        else if (strcmp(unit, "s") == 0 || strcmp(unit, "sec") == 0 || strcmp(unit, "secs") == 0 || strcmp(unit, "second") == 0 || strcmp(unit, "seconds") == 0) mult = 1000.0;
        else if (strcmp(unit, "m") == 0 || strcmp(unit, "min") == 0 || strcmp(unit, "mins") == 0 || strcmp(unit, "minute") == 0 || strcmp(unit, "minutes") == 0) mult = 60000.0;
        else if (strcmp(unit, "h") == 0 || strcmp(unit, "hr") == 0 || strcmp(unit, "hrs") == 0 || strcmp(unit, "hour") == 0 || strcmp(unit, "hours") == 0) mult = 3600000.0;
        else if (strcmp(unit, "d") == 0 || strcmp(unit, "day") == 0 || strcmp(unit, "days") == 0) mult = 86400000.0;
        else return false;
        total += val * mult;
        any = true;
    }
    if (!any) return false;
    *out = (int64_t)(total + 0.5);
    return true;
}

const char *state_dir(char *out, size_t n) {
    if (g_state_dir_override[0]) {
        snprintf(out, n, "%s", g_state_dir_override);
        return out;
    }
    const char *env = getenv("AUTH_ROUTER_STATE_DIR");
    if (env && *env) {
        snprintf(out, n, "%s", env);
        str_trim(out);
        if (*out) return out;
    }
    env = getenv("CREST_AUTH_HOME");
    if (env && *env) {
        snprintf(out, n, "%s", env);
        str_trim(out);
        if (*out) return out;
    }
    const char *xdg = getenv("XDG_STATE_HOME");
    if (xdg && *xdg) {
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "%s", xdg);
        char *t = str_trim(tmp);
        if (*t) {
            snprintf(out, n, "%s/crest-auth", t);
            return out;
        }
    }
    const char *home = getenv("HOME");
    snprintf(out, n, "%s/.local/state/crest-auth", home ? home : "");
    return out;
}

bool state_path(const char *rel, char *out, size_t n) {
    char dir[1024];
    state_dir(dir, sizeof(dir));
    int r = snprintf(out, n, "%s%s%s", dir, (rel[0] == '/') ? "" : "/", rel);
    return r > 0 && (size_t)r < n;
}

bool ensure_dir(const char *path, mode_t mode) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return false;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return false;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return false;
    return true;
}

bool file_read(const char *path, char **out, size_t *out_len, bool *not_found) {
    if (not_found) *not_found = false;
    *out = NULL;
    if (out_len) *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT && not_found) *not_found = true;
        return false;
    }
    sb_t sb;
    sb_init(&sb);
    char buf[4096];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            sb_free(&sb);
            return false;
        }
        if (r == 0) break;
        sb_putn(&sb, buf, (size_t)r);
    }
    close(fd);
    *out = sb.data;
    if (out_len) *out_len = sb.len;
    return true;
}

bool file_write_0600(const char *path, const char *data, size_t len) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        if (!ensure_dir(dir, 0700)) return false;
    }
    char tmp[1088];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    fchmod(fd, 0600);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmp);
            return false;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return false;
    }
    if (close(fd) != 0) {
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    chmod(path, 0600);
    return true;
}

bool file_lock(const char *path, int *fd_out, char *err, size_t err_n) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        ensure_dir(dir, 0700);
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err, err_n, "%s: %s", path, strerror(errno));
        return false;
    }
    int64_t give_up = now_ms() + 6 * 60 * 1000;
    for (;;) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            *fd_out = fd;
            return true;
        }
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            snprintf(err, err_n, "%s: %s", path, strerror(errno));
            close(fd);
            return false;
        }
        if (now_ms() > give_up) {
            snprintf(err, err_n, "%s: another process has held the lock for too long", path);
            close(fd);
            return false;
        }
        sleep_ms(500);
    }
}

void file_unlock(int fd) {
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}
