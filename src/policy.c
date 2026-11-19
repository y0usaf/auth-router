#define _POSIX_C_SOURCE 200809L

#include "policy.h"
#include <stdio.h>
#include <string.h>

static int bucket_rank(const route_req_t *req, const char *name) {
    int pref = (req->prefer_id && req->prefer_id[0] && strcmp(name, req->prefer_id) == 0) ? 0 : 1;
    int top = (req->top_id && req->top_id[0] && strcmp(name, req->top_id) == 0) ? 0 : 1;
    int rot = (req->rotate_from_id && req->rotate_from_id[0] && strcmp(name, req->rotate_from_id) == 0) ? 1 : 0;
    return (pref << 2) | (top << 1) | rot;
}

static int64_t effective_hold_until(const hold_list_t *holds, const char *id, const char *model, int64_t now) {
    if (!holds) return 0;
    int64_t max_u = 0;
    const char *m = model ? model : "";
    for (size_t i = 0; i < holds->len; i++) {
        const hold_t *h = &holds->items[i];
        if (!h->id || strcmp(h->id, id) != 0) continue;
        if (h->model && h->model[0] != '\0' && strcmp(h->model, m) != 0) continue;
        if (h->until > now && h->until > max_u) max_u = h->until;
    }
    return max_u;
}

static bool is_model_unavail(const unavail_list_t *unavail, const char *id, const char *model) {
    if (!unavail || !model || !model[0]) return false;
    for (size_t i = 0; i < unavail->len; i++) {
        const unavail_t *u = &unavail->items[i];
        if (u->id && u->model && strcmp(u->id, id) == 0 && strcmp(u->model, model) == 0) {
            return true;
        }
    }
    return false;
}

bool policy_route(const route_req_t *req, policy_res_t *out, char *err, size_t err_n) {
    (void)err;
    (void)err_n;
    memset(out, 0, sizeof(*out));
    out->route_rank = -1;
    out->http_status = 404;

    if (!req || !req->routes || req->route_cnt == 0) {
        return true;
    }

    const char *excl = (req->exclude_provider && req->exclude_provider[0]) ? req->exclude_provider : NULL;
    bool has_primary = false;
    int64_t primary_rank = 0;
    for (size_t i = 0; i < req->route_cnt; i++) {
        const route_cand_t *rc = &req->routes[i];
        if (excl && strcmp(rc->provider, excl) == 0) continue;
        if (!has_primary || rc->rank < primary_rank) {
            primary_rank = rc->rank;
            has_primary = true;
        }
    }
    if (!has_primary) {
        return true;
    }

    bool has_best = false;
    int64_t best_rank = 0;
    int best_bucket = 0;
    size_t best_pos = 0;
    const route_cand_t *best_route = NULL;
    const cred_t *best_cred = NULL;

    bool has_wait = false;
    int64_t min_wait_ms = 0;
    bool has_primary_wait = false;
    int64_t primary_min_wait_ms = 0;
    int64_t ready_cnt = 0;

    size_t pool_len = req->pool ? req->pool->len : 0;

    for (size_t i = 0; i < req->route_cnt; i++) {
        const route_cand_t *rc = &req->routes[i];
        if (excl && strcmp(rc->provider, excl) == 0) continue;

        for (size_t j = 0; j < pool_len; j++) {
            const cred_t *c = &req->pool->items[j];
            if (!c->name || !c->provider || !c->id || !c->kind) continue;
            if (strcmp(c->kind, "acp") == 0) continue;
            if (strcmp(c->provider, rc->provider) != 0) continue;

            bool unavail = is_model_unavail(req->unavail, c->id, rc->model);
            int64_t hold_until = effective_hold_until(req->holds, c->id, rc->model, req->now_ms);
            bool held = (hold_until > req->now_ms);

            if (held && !unavail) {
                int64_t wait_ms = hold_until - req->now_ms;
                if (!has_wait || wait_ms < min_wait_ms) {
                    min_wait_ms = wait_ms;
                    has_wait = true;
                }
                if (rc->rank == primary_rank && (!has_primary_wait || wait_ms < primary_min_wait_ms)) {
                    primary_min_wait_ms = wait_ms;
                    has_primary_wait = true;
                }
            }

            if (!unavail && !held) {
                ready_cnt++;
                int b = bucket_rank(req, c->name);
                bool better = false;
                if (!has_best) {
                    better = true;
                } else if (rc->rank != best_rank) {
                    better = rc->rank < best_rank;
                } else if (b != best_bucket) {
                    better = b < best_bucket;
                } else if (j < best_pos) {
                    better = true;
                }
                if (better) {
                    has_best = true;
                    best_rank = rc->rank;
                    best_bucket = b;
                    best_pos = j;
                    best_route = rc;
                    best_cred = c;
                }
            }
        }
    }

    if (has_best) {
        out->has_selected = true;
        snprintf(out->selected_id, sizeof(out->selected_id), "%s", best_cred->name);
        snprintf(out->provider, sizeof(out->provider), "%s", best_route->provider);
        snprintf(out->model, sizeof(out->model), "%s", best_route->model);
        out->route_rank = best_route->rank;
        out->is_fallback = (best_route->rank > primary_rank);
        out->primary_retry_ms = (out->is_fallback && has_primary_wait) ? primary_min_wait_ms : 0;
        out->http_status = 200;
        out->retry_ms = 0;
        out->retry_s = 0;
        out->ready_cnt = ready_cnt;
    } else {
        out->has_selected = false;
        out->route_rank = -1;
        out->is_fallback = false;
        out->primary_retry_ms = has_primary_wait ? primary_min_wait_ms : 0;
        out->http_status = (has_wait && min_wait_ms > 0) ? 429 : 404;
        out->retry_ms = has_wait ? min_wait_ms : 0;
        out->retry_s = (has_wait && min_wait_ms > 0) ? ((min_wait_ms + 999) / 1000) : 0;
        out->ready_cnt = 0;
    }

    return true;
}

bool policy_select(const policy_req_t *req, policy_res_t *out, char *err, size_t err_n) {
    route_cand_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.rank = 0;
    if ((req->provider && strlen(req->provider) >= sizeof(rc.provider)) ||
        (req->model && strlen(req->model) >= sizeof(rc.model))) {
        snprintf(err, err_n, "route provider/model too long");
        return false;
    }
    snprintf(rc.provider, sizeof(rc.provider), "%s", req->provider ? req->provider : "");
    snprintf(rc.model, sizeof(rc.model), "%s", req->model ? req->model : "");

    route_req_t rr;
    memset(&rr, 0, sizeof(rr));
    rr.now_ms = req->now_ms;
    rr.routes = &rc;
    rr.route_cnt = 1;
    rr.exclude_provider = "";
    rr.prefer_id = req->prefer_id;
    rr.top_id = req->top_id;
    rr.rotate_from_id = req->rotate_from_id;
    rr.pool = req->pool;
    rr.holds = req->holds;
    rr.unavail = req->unavail;
    return policy_route(&rr, out, err, err_n);
}
