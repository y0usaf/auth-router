#define _POSIX_C_SOURCE 200809L

#include "policy.h"
#include "psy.h"
#include "router_psy_builtin.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static psy_val_t v_i64(int64_t x) {
    psy_val_t v;
    memset(&v, 0, sizeof(v));
    v.kind = PSY_TY_I64;
    v.i64 = x;
    return v;
}

static psy_val_t v_bool(bool b) {
    psy_val_t v;
    memset(&v, 0, sizeof(v));
    v.kind = PSY_TY_BOOL;
    v.b = b;
    return v;
}

static psy_val_t v_str(const char *s) {
    psy_val_t v;
    memset(&v, 0, sizeof(v));
    v.kind = PSY_TY_STR;
    snprintf(v.str, sizeof(v.str), "%s", s ? s : "");
    return v;
}

static void set_cfg(psy_rt_t *rt, const psy_prog_t *prog, const char *name, psy_val_t val) {
    int c = psy_find_config_col(prog, name);
    if (c >= 0) rt->config[c] = val;
}

static void set_col(const psy_table_t *t, psy_row_t *row, const char *name, psy_val_t val) {
    int c = psy_find_col(t, name);
    if (c >= 0) row->vals[c] = val;
}

static bool check_str_cap(const char *s, int cap, const char *label, char *err, size_t err_n) {
    if (s && (int)strlen(s) > cap) {
        snprintf(err, err_n, "psy policy %s exceeds str[%d] limit", label, cap);
        return false;
    }
    return true;
}

static int bucket_rank(const route_req_t *req, const char *name) {
    int pref = (req->prefer_id && req->prefer_id[0] && strcmp(name, req->prefer_id) == 0) ? 0 : 1;
    int top = (req->top_id && req->top_id[0] && strcmp(name, req->top_id) == 0) ? 0 : 1;
    int rot = (req->rotate_from_id && req->rotate_from_id[0] && strcmp(name, req->rotate_from_id) == 0) ? 1 : 0;
    return (pref << 2) | (top << 1) | rot;
}

static int64_t effective_hold_until(const hold_list_t *holds, const char *id, const char *model, int64_t now) {
    if (!holds) return 0;
    int64_t max_u = 0;
    for (size_t i = 0; i < holds->len; i++) {
        const hold_t *h = &holds->items[i];
        if (strcmp(h->id, id) != 0) continue;
        if (h->model[0] != '\0' && strcmp(h->model, model ? model : "") != 0) continue;
        if (h->until > now && h->until > max_u) max_u = h->until;
    }
    return max_u;
}

static bool is_model_unavail(const unavail_list_t *unavail, const char *id, const char *model) {
    if (!unavail || !model || !model[0]) return false;
    for (size_t i = 0; i < unavail->len; i++) {
        if (strcmp(unavail->items[i].id, id) == 0 && strcmp(unavail->items[i].model, model) == 0) {
            return true;
        }
    }
    return false;
}

static bool eval_single_route_chunk(psy_rt_t *rt,
                                    const psy_prog_t *prog,
                                    const route_req_t *req,
                                    const route_cand_t *rc,
                                    const cred_t *const *creds,
                                    size_t cred_cnt,
                                    policy_res_t *chunk_res,
                                    char *err,
                                    size_t err_n) {
    int ti_routes = psy_find_table(prog, "routes");
    int ti_logins = psy_find_table(prog, "logins");
    int ti_holds = psy_find_table(prog, "holds");
    int ti_unavail = psy_find_table(prog, "unavailable");
    int ti_audit = psy_find_table(prog, "audit_log");
    if (ti_routes < 0 || ti_logins < 0 || ti_holds < 0 || ti_unavail < 0 || ti_audit < 0) {
        snprintf(err, err_n, "psy policy missing required tables");
        return false;
    }

    psy_rt_init(rt, prog);
    set_cfg(rt, prog, "now_ms", v_i64(req->now_ms));
    set_cfg(rt, prog, "exclude_provider", v_str(req->exclude_provider ? req->exclude_provider : ""));
    set_cfg(rt, prog, "prefer_id", v_str(req->prefer_id ? req->prefer_id : ""));
    set_cfg(rt, prog, "top_id", v_str(req->top_id ? req->top_id : ""));
    set_cfg(rt, prog, "rotate_from_id", v_str(req->rotate_from_id ? req->rotate_from_id : ""));
    set_cfg(rt, prog, "req_seq", v_i64(1));

    const psy_table_t *tr = &prog->tables[ti_routes];
    psy_table_data_t *dr = &rt->tables[ti_routes];
    dr->count = 1;
    memset(&dr->rows[0], 0, sizeof(psy_row_t));
    set_col(tr, &dr->rows[0], "rank", v_i64(rc->rank));
    set_col(tr, &dr->rows[0], "provider", v_str(rc->provider));
    set_col(tr, &dr->rows[0], "model", v_str(rc->model));

    const psy_table_t *tl = &prog->tables[ti_logins];
    psy_table_data_t *dl = &rt->tables[ti_logins];
    const psy_table_t *th = &prog->tables[ti_holds];
    psy_table_data_t *dh = &rt->tables[ti_holds];
    const psy_table_t *tu = &prog->tables[ti_unavail];
    psy_table_data_t *du = &rt->tables[ti_unavail];

    dl->count = 0;
    dh->count = 0;
    du->count = 0;

    for (size_t i = 0; i < cred_cnt; i++) {
        const cred_t *c = creds[i];
        psy_row_t *row = &dl->rows[dl->count++];
        memset(row, 0, sizeof(*row));
        set_col(tl, row, "id", v_str(c->name));
        set_col(tl, row, "provider", v_str(c->provider));
        set_col(tl, row, "order_pos", v_i64((int64_t)i));
        set_col(tl, row, "finished", v_bool(true));
        set_col(tl, row, "access_tok", v_str(""));
        set_col(tl, row, "refresh_tok", v_str(""));

        int64_t u_ms = effective_hold_until(req->holds, c->id, rc->model, req->now_ms);
        if (u_ms > req->now_ms && dh->count < th->max_rows) {
            psy_row_t *hrow = &dh->rows[dh->count++];
            memset(hrow, 0, sizeof(*hrow));
            set_col(th, hrow, "id", v_i64((int64_t)dh->count));
            set_col(th, hrow, "login_id", v_str(c->name));
            set_col(th, hrow, "model", v_str(rc->model));
            set_col(th, hrow, "until_ms", v_i64(u_ms));
        }

        if (is_model_unavail(req->unavail, c->id, rc->model) && du->count < tu->max_rows) {
            psy_row_t *urow = &du->rows[du->count++];
            memset(urow, 0, sizeof(*urow));
            set_col(tu, urow, "id", v_i64((int64_t)du->count));
            set_col(tu, urow, "login_id", v_str(c->name));
            set_col(tu, urow, "model", v_str(rc->model));
        }
    }

    if (!psy_rt_step(rt, prog)) {
        snprintf(err, err_n, "psy policy step failed: %s", rt->err);
        return false;
    }

    memset(chunk_res, 0, sizeof(*chunk_res));
    const psy_table_t *ta = &prog->tables[ti_audit];
    const psy_table_data_t *da = &rt->tables[ti_audit];
    if (da->count > 0) {
        const psy_row_t *arow = &da->rows[0];
        int c_sel = psy_find_col(ta, "selected_login");
        int c_prov = psy_find_col(ta, "provider");
        int c_mod = psy_find_col(ta, "model");
        int c_rank = psy_find_col(ta, "route_rank");
        int c_st = psy_find_col(ta, "http_status");
        int c_rm = psy_find_col(ta, "retry_ms");
        int c_rs = psy_find_col(ta, "retry_s");
        int c_rc = psy_find_col(ta, "ready_cnt");

        chunk_res->http_status = (c_st >= 0) ? (int)arow->vals[c_st].i64 : 404;
        chunk_res->retry_ms = (c_rm >= 0) ? arow->vals[c_rm].i64 : 0;
        chunk_res->retry_s = (c_rs >= 0) ? arow->vals[c_rs].i64 : 0;
        chunk_res->ready_cnt = (c_rc >= 0) ? arow->vals[c_rc].i64 : 0;
        if (chunk_res->http_status == 200 && c_sel >= 0 && arow->vals[c_sel].str[0]) {
            chunk_res->has_selected = true;
            snprintf(chunk_res->selected_id, sizeof(chunk_res->selected_id), "%s", arow->vals[c_sel].str);
            snprintf(chunk_res->provider, sizeof(chunk_res->provider), "%s", c_prov >= 0 ? arow->vals[c_prov].str : rc->provider);
            snprintf(chunk_res->model, sizeof(chunk_res->model), "%s", c_mod >= 0 ? arow->vals[c_mod].str : rc->model);
            chunk_res->route_rank = (c_rank >= 0) ? arow->vals[c_rank].i64 : rc->rank;
        }
    }
    psy_rt_teardown_mounts(rt, prog);
    return true;
}

bool policy_route(const route_req_t *req, policy_res_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    out->route_rank = -1;
    out->http_status = 404;

    if (!check_str_cap(req->exclude_provider, 64, "exclude_provider", err, err_n) ||
        !check_str_cap(req->prefer_id, 64, "prefer_id", err, err_n) ||
        !check_str_cap(req->top_id, 64, "top_id", err, err_n) ||
        !check_str_cap(req->rotate_from_id, 64, "rotate_from_id", err, err_n)) {
        return false;
    }

    for (size_t i = 0; i < req->route_cnt; i++) {
        if (!check_str_cap(req->routes[i].provider, 64, "route provider", err, err_n) ||
            !check_str_cap(req->routes[i].model, 64, "route model", err, err_n)) {
            return false;
        }
    }
    if (req->pool) {
        for (size_t i = 0; i < req->pool->len; i++) {
            if (!check_str_cap(req->pool->items[i].name, 64, "login name", err, err_n) ||
                !check_str_cap(req->pool->items[i].provider, 64, "login provider", err, err_n)) {
                return false;
            }
        }
    }

    route_cand_t *allowed = calloc(req->route_cnt ? req->route_cnt : 1, sizeof(route_cand_t));
    size_t allowed_cnt = 0;
    for (size_t i = 0; i < req->route_cnt; i++) {
        if (req->exclude_provider && req->exclude_provider[0] &&
            strcmp(req->routes[i].provider, req->exclude_provider) == 0) {
            continue;
        }
        allowed[allowed_cnt++] = req->routes[i];
    }

    for (size_t i = 1; i < allowed_cnt; i++) {
        route_cand_t cur = allowed[i];
        size_t j = i;
        while (j > 0 && allowed[j - 1].rank > cur.rank) {
            allowed[j] = allowed[j - 1];
            j--;
        }
        allowed[j] = cur;
    }

    if (allowed_cnt == 0) {
        free(allowed);
        return true;
    }

    psy_prog_t *prog = calloc(1, sizeof(*prog));
    psy_rt_t *rt = calloc(1, sizeof(*rt));
    if (!prog || !rt) {
        free(allowed);
        free(prog);
        free(rt);
        snprintf(err, err_n, "out of memory");
        return false;
    }

    const char *policy_src = router_psy_builtin;
    char *ext_src = NULL;
    const char *env_policy = getenv("AUTH_ROUTER_POLICY");
    if (env_policy && *env_policy) {
        bool nf = false;
        if (file_read(env_policy, &ext_src, NULL, &nf) && ext_src) {
            policy_src = ext_src;
        }
    }

    if (!psy_parse(prog, "router.psy", policy_src) || !psy_check(prog)) {
        snprintf(err, err_n, "psy policy error: %s", prog->err);
        free(allowed);
        free(ext_src);
        free(rt);
        free(prog);
        return false;
    }

    int ti_logins = psy_find_table(prog, "logins");
    size_t chunk_cap = (ti_logins >= 0 && prog->tables[ti_logins].max_rows > 0)
                           ? (size_t)prog->tables[ti_logins].max_rows
                           : 4;

    int64_t primary_rank = allowed[0].rank;
    int64_t primary_min_wait = 0;
    int64_t global_min_wait = 0;
    bool found_any = false;
    policy_res_t winner;
    memset(&winner, 0, sizeof(winner));

    for (size_t ri = 0; ri < allowed_cnt; ri++) {
        const route_cand_t *rc = &allowed[ri];
        bool is_primary = (rc->rank == primary_rank);
        if (found_any && !is_primary) break;

        size_t pcnt = 0;
        const cred_t **matching = NULL;
        if (req->pool && req->pool->len > 0) {
            matching = calloc(req->pool->len, sizeof(cred_t *));
            for (size_t i = 0; i < req->pool->len; i++) {
                if (strcmp(req->pool->items[i].provider, rc->provider) == 0) {
                    matching[pcnt++] = &req->pool->items[i];
                }
            }
        }

        for (size_t i = 1; i < pcnt; i++) {
            const cred_t *cur = matching[i];
            int cur_b = bucket_rank(req, cur->name);
            size_t j = i;
            while (j > 0) {
                int prev_b = bucket_rank(req, matching[j - 1]->name);
                if (prev_b <= cur_b) break;
                matching[j] = matching[j - 1];
                j--;
            }
            matching[j] = cur;
        }

        size_t offset = 0;
        do {
            size_t take = (pcnt > offset) ? (pcnt - offset) : 0;
            if (take > chunk_cap) take = chunk_cap;

            policy_res_t cres;
            if (!eval_single_route_chunk(rt, prog, req, rc, matching ? (matching + offset) : NULL, take,
                                         &cres, err, err_n)) {
                free(matching);
                free(allowed);
                free(ext_src);
                free(rt);
                free(prog);
                return false;
            }

            if (cres.has_selected) {
                if (!found_any) {
                    winner = cres;
                    found_any = true;
                }
            } else if (cres.retry_ms > 0) {
                if (global_min_wait == 0 || cres.retry_ms < global_min_wait) {
                    global_min_wait = cres.retry_ms;
                }
                if (is_primary && (primary_min_wait == 0 || cres.retry_ms < primary_min_wait)) {
                    primary_min_wait = cres.retry_ms;
                }
            }

            offset += take;
        } while ((!found_any || is_primary) && offset < pcnt);

        free(matching);
    }

    if (found_any) {
        *out = winner;
        out->is_fallback = (winner.route_rank > primary_rank);
        out->primary_retry_ms = out->is_fallback ? primary_min_wait : 0;
        out->http_status = 200;
        out->retry_ms = 0;
        out->retry_s = 0;
    } else {
        out->has_selected = false;
        out->selected_id[0] = '\0';
        out->provider[0] = '\0';
        out->model[0] = '\0';
        out->route_rank = -1;
        out->is_fallback = false;
        out->primary_retry_ms = primary_min_wait;
        out->http_status = (global_min_wait > 0) ? 429 : 404;
        out->retry_ms = global_min_wait;
        out->retry_s = (global_min_wait + 999) / 1000;
        out->ready_cnt = 0;
    }

    free(allowed);
    free(ext_src);
    free(rt);
    free(prog);
    return true;
}

bool policy_select(const policy_req_t *req, policy_res_t *out, char *err, size_t err_n) {
    route_cand_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.rank = 0;
    if (!check_str_cap(req->provider, 64, "provider", err, err_n) ||
        !check_str_cap(req->model, 64, "model", err, err_n)) {
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
