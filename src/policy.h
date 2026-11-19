#ifndef POLICY_H
#define POLICY_H

#include "store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int64_t rank;
    char provider[128];
    char model[128];
} route_cand_t;

typedef struct {
    int64_t now_ms;
    const route_cand_t *routes;
    size_t route_cnt;
    const char *exclude_provider;
    const char *prefer_id;
    const char *top_id;
    const char *rotate_from_id;
    const cred_list_t *pool;
    const hold_list_t *holds;
    const unavail_list_t *unavail;
} route_req_t;

typedef struct {
    bool has_selected;
    char selected_id[128];
    char provider[128];
    char model[128];
    int64_t route_rank;
    bool is_fallback;
    int64_t primary_retry_ms;
    int http_status;
    int64_t retry_ms;
    int64_t retry_s;
    int64_t ready_cnt;
} policy_res_t;

typedef struct {
    int64_t now_ms;
    const char *provider;
    const char *model;
    const char *prefer_id;
    const char *top_id;
    const char *rotate_from_id;
    const cred_list_t *pool;
    const hold_list_t *holds;
    const unavail_list_t *unavail;
} policy_req_t;

bool policy_route(const route_req_t *req, policy_res_t *out, char *err, size_t err_n);
bool policy_select(const policy_req_t *req, policy_res_t *out, char *err, size_t err_n);

#endif
