#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int status;
    char *body;
    size_t body_len;
} http_resp_t;

bool http_request(const char *method,
                  const char *url,
                  const char *body,
                  const char **headers,
                  size_t header_cnt,
                  int64_t timeout_ms,
                  http_resp_t *out,
                  char *err,
                  size_t err_n);

void http_resp_free(http_resp_t *r);

bool callback_open(const char *host, int port, int *sock_out, int *actual_port, char *err, size_t err_n);
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
                   size_t err_n);

#endif
