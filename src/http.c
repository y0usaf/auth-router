#define _POSIX_C_SOURCE 200809L

#include "http.h"
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define HTTP_MAX_RESPONSE_BYTES (4 * 1024 * 1024)

typedef struct {
    bool is_https;
    char host[256];
    char port[16];
    int port_num;
    char path[2048];
} parsed_url_t;

typedef struct {
    int fd;
    int64_t deadline_ms;
} bio_ctx_t;

typedef struct {
    bool initialized;
    bool ca_loaded;
    pid_t pid;
    char ca_path[1024];
    mbedtls_x509_crt cacert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} tls_cache_t;

static tls_cache_t g_tls_cache;

static bool has_ctl_or_crlf(const char *s) {
    if (!s) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) return true;
    }
    return false;
}

static bool has_crlf(const char *s) {
    if (!s) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\r' || *p == '\n') return true;
    }
    return false;
}

static void set_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

static bool parse_url(const char *url, parsed_url_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    if (!url || !url[0] || has_ctl_or_crlf(url)) {
        snprintf(err, err_n, "invalid character in URL");
        return false;
    }
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) {
        out->is_https = true;
        p += 8;
        out->port_num = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        out->is_https = false;
        p += 7;
        out->port_num = 80;
    } else {
        snprintf(err, err_n, "unsupported URL scheme");
        return false;
    }
    const char *host_start = p;
    const char *host_end = NULL;
    if (*p == '[') {
        host_start = p + 1;
        const char *rb = strchr(host_start, ']');
        if (!rb) {
            snprintf(err, err_n, "invalid IPv6 host in URL");
            return false;
        }
        host_end = rb;
        p = rb + 1;
    } else {
        while (*p && *p != ':' && *p != '/' && *p != '?') {
            if (*p == ' ' || *p == '\t') {
                snprintf(err, err_n, "invalid whitespace in URL host");
                return false;
            }
            p++;
        }
        host_end = p;
    }
    size_t hlen = (size_t)(host_end - host_start);
    if (hlen == 0 || hlen >= sizeof(out->host)) {
        snprintf(err, err_n, "invalid host in URL");
        return false;
    }
    memcpy(out->host, host_start, hlen);
    out->host[hlen] = '\0';

    if (*p == ':') {
        p++;
        const char *ps = p;
        while (*p && *p >= '0' && *p <= '9') p++;
        size_t plen = (size_t)(p - ps);
        if (plen == 0 || plen >= sizeof(out->port)) {
            snprintf(err, err_n, "invalid port in URL");
            return false;
        }
        memcpy(out->port, ps, plen);
        out->port[plen] = '\0';
        int64_t pn = 0;
        if (!str_to_i64(out->port, &pn) || pn <= 0 || pn > 65535) {
            snprintf(err, err_n, "invalid port number in URL");
            return false;
        }
        out->port_num = (int)pn;
    } else {
        snprintf(out->port, sizeof(out->port), "%d", out->port_num);
    }

    if (*p && *p != '/' && *p != '?') {
        snprintf(err, err_n, "invalid URL path separator");
        return false;
    }
    for (const char *q = p; *q; q++) {
        if (*q == ' ' || *q == '\t') {
            snprintf(err, err_n, "invalid whitespace in URL path");
            return false;
        }
    }

    int pn = 0;
    if (*p == '\0') {
        pn = snprintf(out->path, sizeof(out->path), "/");
    } else if (*p == '?') {
        pn = snprintf(out->path, sizeof(out->path), "/%s", p);
    } else {
        pn = snprintf(out->path, sizeof(out->path), "%s", p);
    }
    if (pn < 0 || (size_t)pn >= sizeof(out->path)) {
        snprintf(err, err_n, "URL path exceeds maximum length");
        return false;
    }
    return true;
}

static int poll_wait_fd(int fd, short events, int64_t deadline_ms) {
    for (;;) {
        int64_t rem = deadline_ms - now_ms();
        if (rem <= 0) return 0;
        int ms = (rem > 60000) ? 60000 : (int)rem;
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;
        int r = poll(&pfd, 1, ms);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        return r;
    }
}

static int tcp_connect_timeout(const char *host, const char *port, int64_t deadline_ms, char *err, size_t err_n) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        snprintf(err, err_n, "resolve %s:%s: %s", host, port, gai_strerror(gai));
        return -1;
    }

    int sock = -1;
    int last_err = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_err = errno;
            continue;
        }
        set_cloexec(fd);
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);

        int c = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (c == 0) {
            sock = fd;
            break;
        }
        if (errno == EINPROGRESS) {
            int pr = poll_wait_fd(fd, POLLOUT, deadline_ms);
            if (pr > 0) {
                int so_err = 0;
                socklen_t slen = sizeof(so_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) == 0 && so_err == 0) {
                    sock = fd;
                    break;
                }
                last_err = so_err ? so_err : ECONNREFUSED;
            } else if (pr == 0) {
                last_err = ETIMEDOUT;
            } else {
                last_err = errno;
            }
        } else {
            last_err = errno;
        }
        close(fd);
    }
    freeaddrinfo(res);

    if (sock < 0) {
        snprintf(err, err_n, "connect %s:%s: %s", host, port, strerror(last_err ? last_err : ECONNREFUSED));
    }
    return sock;
}

static int bio_send_cb(void *ctx, const unsigned char *buf, size_t len) {
    bio_ctx_t *b = (bio_ctx_t *)ctx;
    for (;;) {
        ssize_t w = send(b->fd, buf, len, MSG_NOSIGNAL);
        if (w >= 0) return (int)w;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int pr = poll_wait_fd(b->fd, POLLOUT, b->deadline_ms);
            if (pr == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
            if (pr < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
            continue;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
}

static int bio_recv_cb(void *ctx, unsigned char *buf, size_t len) {
    bio_ctx_t *b = (bio_ctx_t *)ctx;
    for (;;) {
        ssize_t r = recv(b->fd, buf, len, 0);
        if (r >= 0) return (int)r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int pr = poll_wait_fd(b->fd, POLLIN, b->deadline_ms);
            if (pr == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
            if (pr < 0) return MBEDTLS_ERR_NET_RECV_FAILED;
            continue;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

static const char *resolve_ca_bundle_path(void) {
    const char *candidates[4];
    candidates[0] = getenv("AUTH_ROUTER_CA_FILE");
    candidates[1] = getenv("SSL_CERT_FILE");
    candidates[2] = "/etc/ssl/certs/ca-bundle.crt";
    candidates[3] = "/etc/ssl/certs/ca-certificates.crt";

    for (size_t i = 0; i < 4; i++) {
        const char *path = candidates[i];
        if (!path || !*path) continue;
        if (access(path, R_OK) == 0) return path;
    }
    return NULL;
}

static bool tls_cache_prepare(char *err, size_t err_n) {
    if (!g_tls_cache.initialized) {
        psa_status_t psa_rc = psa_crypto_init();
        if (psa_rc != PSA_SUCCESS) {
            snprintf(err, err_n, "psa_crypto_init failed: %d", (int)psa_rc);
            return false;
        }
        mbedtls_x509_crt_init(&g_tls_cache.cacert);
        mbedtls_entropy_init(&g_tls_cache.entropy);
        mbedtls_ctr_drbg_init(&g_tls_cache.ctr_drbg);

        const char *pers = "auth-router";
        int rc = mbedtls_ctr_drbg_seed(&g_tls_cache.ctr_drbg, mbedtls_entropy_func, &g_tls_cache.entropy,
                                       (const unsigned char *)pers, strlen(pers));
        if (rc != 0) {
            snprintf(err, err_n, "tls drbg seed failed: -0x%04x", (unsigned)(-rc));
            mbedtls_x509_crt_free(&g_tls_cache.cacert);
            mbedtls_ctr_drbg_free(&g_tls_cache.ctr_drbg);
            mbedtls_entropy_free(&g_tls_cache.entropy);
            return false;
        }
        g_tls_cache.initialized = true;
        g_tls_cache.pid = getpid();
    } else if (g_tls_cache.pid != getpid()) {
        pid_t cur = getpid();
        int rc = mbedtls_ctr_drbg_reseed(&g_tls_cache.ctr_drbg, (const unsigned char *)&cur, sizeof(cur));
        if (rc != 0) {
            snprintf(err, err_n, "tls drbg reseed failed: -0x%04x", (unsigned)(-rc));
            return false;
        }
        g_tls_cache.pid = cur;
    }

    const char *path = resolve_ca_bundle_path();
    if (!path) {
        snprintf(err, err_n, "unable to load CA certificate bundle");
        return false;
    }

    if (!g_tls_cache.ca_loaded || strcmp(g_tls_cache.ca_path, path) != 0) {
        mbedtls_x509_crt_free(&g_tls_cache.cacert);
        mbedtls_x509_crt_init(&g_tls_cache.cacert);
        g_tls_cache.ca_loaded = false;
        g_tls_cache.ca_path[0] = '\0';

        int rc = mbedtls_x509_crt_parse_file(&g_tls_cache.cacert, path);
        if (rc < 0) {
            mbedtls_x509_crt_free(&g_tls_cache.cacert);
            mbedtls_x509_crt_init(&g_tls_cache.cacert);
            snprintf(err, err_n, "unable to parse CA certificate bundle %s", path);
            return false;
        }
        snprintf(g_tls_cache.ca_path, sizeof(g_tls_cache.ca_path), "%s", path);
        g_tls_cache.ca_loaded = true;
    }

    return true;
}

static bool raw_send_all(int fd, const char *data, size_t len, int64_t deadline_ms, char *err, size_t err_n) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int pr = poll_wait_fd(fd, POLLOUT, deadline_ms);
            if (pr == 0) {
                snprintf(err, err_n, "http send timeout");
                return false;
            }
            if (pr < 0) {
                snprintf(err, err_n, "http send poll error");
                return false;
            }
            continue;
        }
        snprintf(err, err_n, "http send failed: %s", strerror(errno));
        return false;
    }
    return true;
}

static bool tls_send_all(mbedtls_ssl_context *ssl, const char *data, size_t len, char *err, size_t err_n) {
    size_t off = 0;
    while (off < len) {
        int w = mbedtls_ssl_write(ssl, (const unsigned char *)(data + off), len - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        char mbuf[128];
        mbedtls_strerror(w, mbuf, sizeof(mbuf));
        snprintf(err, err_n, "tls write failed: %s", mbuf);
        return false;
    }
    return true;
}

static bool header_prefix_ci(const char *hdr, const char *name) {
    size_t n = strlen(name);
    for (size_t i = 0; i < n; i++) {
        if (!hdr[i]) return false;
        if (tolower((unsigned char)hdr[i]) != tolower((unsigned char)name[i])) return false;
    }
    return hdr[n] == ':';
}

static bool decode_chunked(const char *in, size_t in_len, sb_t *out) {
    size_t pos = 0;
    while (pos < in_len) {
        const char *crlf = NULL;
        for (size_t i = pos; i + 1 < in_len; i++) {
            if (in[i] == '\r' && in[i + 1] == '\n') {
                crlf = in + i;
                break;
            }
        }
        if (!crlf) return false;
        size_t line_len = (size_t)(crlf - (in + pos));
        char hexbuf[32];
        size_t hlen = 0;
        for (size_t i = 0; i < line_len; i++) {
            char c = in[pos + i];
            if (c == ';' || c == ' ' || c == '\t') break;
            if (!isxdigit((unsigned char)c)) return false;
            if (hlen + 1 >= sizeof(hexbuf)) return false;
            hexbuf[hlen++] = c;
        }
        hexbuf[hlen] = '\0';
        if (hlen == 0) return false;
        errno = 0;
        char *end = NULL;
        unsigned long long chunk_sz = strtoull(hexbuf, &end, 16);
        if (errno == ERANGE || !end || *end != '\0') return false;
        pos = (size_t)((crlf + 2) - in);
        if (chunk_sz == 0) {
            if (in_len - pos >= 2 && in[pos] == '\r' && in[pos + 1] == '\n') {
                return true;
            }
            for (size_t i = pos; i + 3 < in_len; i++) {
                if (in[i] == '\r' && in[i + 1] == '\n' && in[i + 2] == '\r' && in[i + 3] == '\n') {
                    return true;
                }
            }
            return false;
        }
        if (chunk_sz > (unsigned long long)(in_len - pos)) return false;
        if (chunk_sz > (unsigned long long)(HTTP_MAX_RESPONSE_BYTES - out->len)) return false;
        sb_putn(out, in + pos, (size_t)chunk_sz);
        pos += (size_t)chunk_sz;
        if (in_len - pos < 2 || in[pos] != '\r' || in[pos + 1] != '\n') return false;
        pos += 2;
    }
    return false;
}

static bool parse_http_response(const char *raw,
                                size_t raw_len,
                                bool require_explicit_framing,
                                http_resp_t *out,
                                char *err,
                                size_t err_n) {
    const char *sep = NULL;
    size_t sep_len = 0;
    for (size_t i = 0; i + 3 < raw_len; i++) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
            sep = raw + i;
            sep_len = 4;
            break;
        }
    }
    if (!sep) {
        for (size_t i = 0; i + 1 < raw_len; i++) {
            if (raw[i] == '\n' && raw[i + 1] == '\n') {
                sep = raw + i;
                sep_len = 2;
                break;
            }
        }
    }
    if (!sep) {
        snprintf(err, err_n, "malformed HTTP response: missing header terminator");
        return false;
    }

    size_t hdr_len = (size_t)(sep - raw);
    const char *body_start = sep + sep_len;
    size_t body_raw_len = raw_len - (size_t)(body_start - raw);

    const char *sp = memchr(raw, ' ', hdr_len);
    if (!sp || (size_t)(sp - raw) + 4 > hdr_len) {
        snprintf(err, err_n, "malformed HTTP status line");
        return false;
    }
    while ((size_t)(sp - raw) < hdr_len && *sp == ' ') sp++;
    int status = atoi(sp);
    if (status < 100 || status > 599) {
        snprintf(err, err_n, "invalid HTTP status code");
        return false;
    }
    out->status = status;

    bool chunked = false;
    int64_t content_length = -1;
    const char *p = raw;
    const char *hdr_end = raw + hdr_len;
    while (p < hdr_end) {
        const char *nl = memchr(p, '\n', (size_t)(hdr_end - p));
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(hdr_end - p);
        if (llen > 0 && p[llen - 1] == '\r') llen--;
        char line[1024];
        size_t clen = (llen < sizeof(line) - 1) ? llen : sizeof(line) - 1;
        memcpy(line, p, clen);
        line[clen] = '\0';
        if (header_prefix_ci(line, "transfer-encoding")) {
            if (str_contains_ci(line + 18, "chunked")) chunked = true;
        } else if (header_prefix_ci(line, "content-length")) {
            char *v = str_trim(line + 15);
            int64_t cl = -1;
            if (!str_to_i64(v, &cl) || cl < 0 || cl > HTTP_MAX_RESPONSE_BYTES) {
                snprintf(err, err_n, "invalid Content-Length header");
                return false;
            }
            content_length = cl;
        }
        if (!nl) break;
        p = nl + 1;
    }

    sb_t body;
    sb_init(&body);
    if (chunked) {
        if (!decode_chunked(body_start, body_raw_len, &body)) {
            sb_free(&body);
            snprintf(err, err_n, "failed to decode chunked HTTP response");
            return false;
        }
    } else if (content_length >= 0) {
        if ((uint64_t)content_length > (uint64_t)body_raw_len) {
            sb_free(&body);
            snprintf(err, err_n, "truncated HTTP response body");
            return false;
        }
        sb_putn(&body, body_start, (size_t)content_length);
    } else {
        if (require_explicit_framing) {
            sb_free(&body);
            snprintf(err, err_n, "unclean TLS close without Content-Length or chunked framing");
            return false;
        }
        sb_putn(&body, body_start, body_raw_len);
    }

    out->body = body.data;
    out->body_len = body.len;
    return true;
}

bool http_request(const char *method,
                  const char *url,
                  const char *body,
                  const char **headers,
                  size_t header_cnt,
                  int64_t timeout_ms,
                  http_resp_t *out,
                  char *err,
                  size_t err_n) {
    memset(out, 0, sizeof(*out));
    const char *m = method ? method : "GET";
    if (!m[0] || has_ctl_or_crlf(m) || strchr(m, ' ') != NULL) {
        snprintf(err, err_n, "invalid HTTP method");
        return false;
    }
    parsed_url_t u;
    if (!parse_url(url, &u, err, err_n)) return false;

    for (size_t i = 0; i < header_cnt; i++) {
        if (!headers[i] || !*headers[i]) continue;
        if (has_crlf(headers[i])) {
            snprintf(err, err_n, "invalid character in HTTP header");
            return false;
        }
    }

    int64_t tmo = (timeout_ms > 0) ? timeout_ms : 15000;
    int64_t deadline = now_ms() + tmo;

    int fd = tcp_connect_timeout(u.host, u.port, deadline, err, err_n);
    if (fd < 0) return false;

    sb_t req;
    sb_init(&req);
    sb_printf(&req, "%s %s HTTP/1.1\r\n", m, u.path);
    bool default_port = (u.is_https && u.port_num == 443) || (!u.is_https && u.port_num == 80);
    if (default_port) {
        sb_printf(&req, "Host: %s\r\n", u.host);
    } else {
        sb_printf(&req, "Host: %s:%d\r\n", u.host, u.port_num);
    }
    sb_puts(&req, "Connection: close\r\n");
    sb_puts(&req, "User-Agent: auth-router/0.1\r\n");

    for (size_t i = 0; i < header_cnt; i++) {
        if (!headers[i] || !*headers[i]) continue;
        if (header_prefix_ci(headers[i], "host") || header_prefix_ci(headers[i], "connection") ||
            header_prefix_ci(headers[i], "content-length")) {
            continue;
        }
        sb_printf(&req, "%s\r\n", headers[i]);
    }
    size_t body_len = body ? strlen(body) : 0;
    if (body) {
        sb_printf(&req, "Content-Length: %zu\r\n", body_len);
    }
    sb_puts(&req, "\r\n");
    if (body && body_len > 0) {
        sb_putn(&req, body, body_len);
    }

    sb_t raw;
    sb_init(&raw);
    bool ok = false;
    bool require_explicit_framing = false;

    if (!u.is_https) {
        if (raw_send_all(fd, req.data, req.len, deadline, err, err_n)) {
            char buf[8192];
            for (;;) {
                ssize_t r = recv(fd, buf, sizeof(buf), 0);
                if (r > 0) {
                    if (raw.len + (size_t)r > HTTP_MAX_RESPONSE_BYTES) {
                        snprintf(err, err_n, "http response exceeds maximum size");
                        break;
                    }
                    sb_putn(&raw, buf, (size_t)r);
                    continue;
                }
                if (r == 0) {
                    ok = true;
                    break;
                }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    int pr = poll_wait_fd(fd, POLLIN, deadline);
                    if (pr == 0) {
                        snprintf(err, err_n, "http recv timeout");
                        break;
                    }
                    if (pr < 0) {
                        snprintf(err, err_n, "http recv poll error");
                        break;
                    }
                    continue;
                }
                snprintf(err, err_n, "http recv failed: %s", strerror(errno));
                break;
            }
        }
    } else {
        if (tls_cache_prepare(err, err_n)) {
            mbedtls_ssl_context ssl;
            mbedtls_ssl_config conf;
            mbedtls_ssl_init(&ssl);
            mbedtls_ssl_config_init(&conf);

            int rc = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                                 MBEDTLS_SSL_PRESET_DEFAULT);
            if (rc != 0) {
                snprintf(err, err_n, "tls config defaults failed: -0x%04x", (unsigned)(-rc));
            } else {
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
                mbedtls_ssl_conf_ca_chain(&conf, &g_tls_cache.cacert, NULL);
                mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_tls_cache.ctr_drbg);
                rc = mbedtls_ssl_setup(&ssl, &conf);
                if (rc != 0) {
                    snprintf(err, err_n, "tls setup failed: -0x%04x", (unsigned)(-rc));
                } else {
                    rc = mbedtls_ssl_set_hostname(&ssl, u.host);
                    if (rc != 0) {
                        snprintf(err, err_n, "tls set hostname failed: -0x%04x", (unsigned)(-rc));
                    } else {
                        bio_ctx_t bctx;
                        bctx.fd = fd;
                        bctx.deadline_ms = deadline;
                        mbedtls_ssl_set_bio(&ssl, &bctx, bio_send_cb, bio_recv_cb, NULL);

                        while ((rc = mbedtls_ssl_handshake(&ssl)) != 0) {
                            if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                                rc == MBEDTLS_ERR_SSL_WANT_WRITE ||
                                rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
                                continue;
                            }
                            uint32_t vflags = mbedtls_ssl_get_verify_result(&ssl);
                            if (vflags != 0) {
                                char vbuf[256];
                                mbedtls_x509_crt_verify_info(vbuf, sizeof(vbuf), "", vflags);
                                str_trim(vbuf);
                                snprintf(err, err_n, "tls certificate verification failed: %s", vbuf);
                            } else {
                                char mbuf[128];
                                mbedtls_strerror(rc, mbuf, sizeof(mbuf));
                                snprintf(err, err_n, "tls handshake failed: %s", mbuf);
                            }
                            break;
                        }

                        if (rc == 0 && tls_send_all(&ssl, req.data, req.len, err, err_n)) {
                            unsigned char buf[8192];
                            for (;;) {
                                int r = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
                                if (r > 0) {
                                    if (raw.len + (size_t)r > HTTP_MAX_RESPONSE_BYTES) {
                                        snprintf(err, err_n, "http response exceeds maximum size");
                                        break;
                                    }
                                    sb_putn(&raw, (const char *)buf, (size_t)r);
                                    continue;
                                }
                                if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                                    ok = true;
                                    break;
                                }
                                if (r == 0) {
                                    require_explicit_framing = true;
                                    ok = true;
                                    break;
                                }
                                if (r == MBEDTLS_ERR_SSL_WANT_READ ||
                                    r == MBEDTLS_ERR_SSL_WANT_WRITE ||
                                    r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
                                    continue;
                                }
                                if (r == MBEDTLS_ERR_NET_CONN_RESET && raw.len > 0) {
                                    require_explicit_framing = true;
                                    ok = true;
                                    break;
                                }
                                char mbuf[128];
                                mbedtls_strerror(r, mbuf, sizeof(mbuf));
                                snprintf(err, err_n, "tls read failed: %s", mbuf);
                                break;
                            }
                            mbedtls_ssl_close_notify(&ssl);
                        }
                    }
                }
            }

            mbedtls_ssl_free(&ssl);
            mbedtls_ssl_config_free(&conf);
        }
    }

    sb_free(&req);
    close(fd);

    if (!ok) {
        sb_free(&raw);
        return false;
    }
    bool parsed = parse_http_response(raw.data, raw.len, require_explicit_framing, out, err, err_n);
    sb_free(&raw);
    return parsed;
}

void http_resp_free(http_resp_t *r) {
    if (!r) return;
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
    r->status = 0;
}

bool callback_open(const char *host, int port, int *sock_out, int *actual_port, char *err, size_t err_n) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, err_n, "socket: %s", strerror(errno));
        return false;
    }
    set_cloexec(fd);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!host || strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        snprintf(err, err_n, "invalid callback host: %s", host);
        return false;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        snprintf(err, err_n, "bind %s:%d: %s", host ? host : "127.0.0.1", port, strerror(errno));
        close(fd);
        return false;
    }
    if (listen(fd, 8) != 0) {
        snprintf(err, err_n, "listen: %s", strerror(errno));
        close(fd);
        return false;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) == 0 && actual_port) {
        *actual_port = (int)ntohs(addr.sin_port);
    }
    *sock_out = fd;
    return true;
}

bool callback_wait(int sock,
                   const char *path,
                   const char *page,
                   int64_t timeout_ms,
                   bool allow_stdin,
                   char *query_out,
                   size_t query_n,
                   bool *from_stdin,
                   bool *timed_out,
                   char *err,
                   size_t err_n) {
    if (from_stdin) *from_stdin = false;
    if (timed_out) *timed_out = false;
    int64_t deadline = now_ms() + timeout_ms;

    for (;;) {
        int64_t rem = deadline - now_ms();
        if (rem <= 0) {
            if (timed_out) *timed_out = true;
            return true;
        }
        struct pollfd pfds[2];
        nfds_t nfds = 0;
        pfds[nfds].fd = sock;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
        if (allow_stdin) {
            pfds[nfds].fd = STDIN_FILENO;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }
        int pr = poll(pfds, nfds, (int)(rem > 1000 ? 1000 : rem));
        if (pr < 0) {
            if (errno == EINTR) continue;
            snprintf(err, err_n, "poll: %s", strerror(errno));
            return false;
        }
        if (pr == 0) continue;

        if (allow_stdin && nfds > 1 && (pfds[1].revents & POLLIN)) {
            if (fgets(query_out, (int)query_n, stdin)) {
                str_trim(query_out);
                if (from_stdin) *from_stdin = true;
                return true;
            }
            allow_stdin = false;
        }

        if (pfds[0].revents & POLLIN) {
            int cfd = accept(sock, NULL, NULL);
            if (cfd < 0) continue;
            set_cloexec(cfd);
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            char req[4096];
            ssize_t r = read(cfd, req, sizeof(req) - 1);
            if (r > 0) {
                req[r] = '\0';
                char *sp1 = strchr(req, ' ');
                char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
                bool matched = false;
                if (sp1 && sp2) {
                    *sp2 = '\0';
                    char *target = sp1 + 1;
                    char *q = strchr(target, '?');
                    if (q) *q++ = '\0';
                    if (strcmp(target, path) == 0) {
                        matched = true;
                        snprintf(query_out, query_n, "%s", q ? q : "");
                    }
                }
                const char *body = matched ? (page ? page : "OK") : "Not found";
                const char *st = matched ? "200 OK" : "404 Not Found";
                char resp[2048];
                int n = snprintf(resp, sizeof(resp),
                                 "HTTP/1.1 %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                                 st, strlen(body), body);
                if (n > 0) {
                    size_t wlen = (size_t)n;
                    if (wlen >= sizeof(resp)) wlen = sizeof(resp) - 1;
                    ssize_t wr = write(cfd, resp, wlen);
                    (void)wr;
                }
                close(cfd);
                if (matched) return true;
            } else {
                close(cfd);
            }
        }
    }
}
