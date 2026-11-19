#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} sb_t;

void sb_init(sb_t *sb);
void sb_free(sb_t *sb);
void sb_putc(sb_t *sb, char c);
void sb_putn(sb_t *sb, const char *s, size_t n);
void sb_puts(sb_t *sb, const char *s);
void sb_printf(sb_t *sb, const char *fmt, ...);

int64_t now_ms(void);
void sleep_ms(int64_t ms);

void sha256_bytes(const uint8_t *data, size_t len, uint8_t out[32]);
void sha256_hex(const char *s, char out[65]);
void base64url_encode(const uint8_t *in, size_t len, char *out);
bool random_bytes(uint8_t *out, size_t len);
void random_b64url(size_t nbytes, char *out);

void url_encode(const char *s, sb_t *out);
void url_decode(const char *s, sb_t *out);

char *str_trim(char *s);
void str_lower_copy(const char *s, char *out, size_t n);
bool str_to_i64(const char *s, int64_t *out);
bool parse_duration_ms(const char *s, int64_t *out);
bool parse_iso8601_ms(const char *s, int64_t *out);
bool str_contains_ci(const char *hay, const char *needle);

void state_dir_set_override(const char *dir);
const char *state_dir(char *out, size_t n);
bool state_path(const char *rel, char *out, size_t n);
bool ensure_dir(const char *path, mode_t mode);
bool file_read(const char *path, char **out, size_t *out_len, bool *not_found);
bool file_write_0600(const char *path, const char *data, size_t len);
bool file_lock(const char *path, int *fd_out, char *err, size_t err_n);
void file_unlock(int fd);

#endif
