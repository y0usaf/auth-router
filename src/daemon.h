#ifndef DAEMON_H
#define DAEMON_H

#include "json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTH_ROUTER_WIRE_VERSION 1

typedef struct {
    const char *socket_path;
    const char *restricted_socket_path;
    const char *state_dir_path;
    bool no_bg_refresh;
} daemon_cfg_t;

typedef enum {
    DAEMON_RPC_OK = 0,
    DAEMON_RPC_UNAVAILABLE,
    DAEMON_RPC_ERR
} daemon_rpc_status_t;

void daemon_default_socket(char *out, size_t n);
int daemon_run(const daemon_cfg_t *cfg, char *err, size_t err_n);

daemon_rpc_status_t daemon_rpc(const char *sock_path,
                               const jval_t *req,
                               int64_t timeout_ms,
                               jval_t **resp_out,
                               char *err,
                               size_t err_n);

jval_t *router_exec_direct(const jval_t *req, bool restricted);

#endif
