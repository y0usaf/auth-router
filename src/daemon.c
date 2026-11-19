#define _POSIX_C_SOURCE 200809L

#include "daemon.h"
#include "oauth.h"
#include "policy.h"
#include "store.h"
#include "util.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 64
#define MAX_JOBS 32
#define MAX_WAITERS 64
#define MAX_INBUF_BYTES (256 * 1024)
#define MAX_OUTBUF_BYTES (1024 * 1024)
#define MAX_JOB_RESULT_BYTES (1024 * 1024)
#define CLIENT_IDLE_TIMEOUT_MS (30 * 1000)

static void set_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

void daemon_default_socket(char *out, size_t n) {
    const char *env = getenv("AUTH_ROUTER_SOCKET");
    if (env && *env) {
        snprintf(out, n, "%s", env);
        return;
    }
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    if (xdg && *xdg) {
        snprintf(out, n, "%s/auth-router.sock", xdg);
        return;
    }
    snprintf(out, n, "/tmp/auth-router-%ld.sock", (long)getuid());
}

static jval_t *make_err(const char *msg) {
    jval_t *r = j_obj();
    j_obj_set(r, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
    j_obj_set(r, "ok", j_bool(false));
    j_obj_set(r, "error", j_str(msg ? msg : "error"));
    return r;
}

static jval_t *make_ok(void) {
    jval_t *r = j_obj();
    j_obj_set(r, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
    j_obj_set(r, "ok", j_bool(true));
    return r;
}

static bool op_allowed_restricted(const char *op) {
    return strcmp(op, "ping") == 0 ||
           strcmp(op, "status") == 0 ||
           strcmp(op, "list") == 0 ||
           strcmp(op, "token") == 0 ||
           strcmp(op, "route") == 0 ||
           strcmp(op, "cool") == 0;
}

static bool cred_needs_refresh(const cred_t *c, int64_t now, int64_t lead_ms, char *err, size_t err_n) {
    if (strcmp(c->kind, "login") == 0) {
        login_list_t logins;
        if (!auth_load(&logins, err, err_n)) return false;
        bool need = false;
        for (size_t i = 0; i < logins.len; i++) {
            if (strcmp(logins.items[i].name, c->name) == 0) {
                if (logins.items[i].refresh[0] &&
                    (!logins.items[i].access[0] ||
                     (logins.items[i].expires > 0 && logins.items[i].expires - now <= lead_ms))) {
                    need = true;
                }
                break;
            }
        }
        login_list_free(&logins);
        return need;
    }
    if (strcmp(c->kind, "oauth") == 0) {
        oa_tok_t tok;
        bool found = false;
        if (!oa_load(c->name, &tok, &found, err, err_n) || !found) return false;
        bool need = tok.refresh && tok.refresh[0] &&
                    (!tok.access || !tok.access[0] ||
                     (tok.expires > 0 && tok.expires - now <= lead_ms));
        oa_tok_free(&tok);
        return need;
    }
    return false;
}

static bool fill_cred_secret(const cred_t *c, jval_t *out, bool refresh_sync, char *err, size_t err_n) {
    j_obj_set(out, "kind", j_str(c->kind));
    j_obj_set(out, "credential_id", j_str(c->id));

    if (strcmp(c->kind, "login") == 0) {
        login_list_t logins;
        if (!auth_load(&logins, err, err_n)) return false;
        const login_t *found = NULL;
        for (size_t i = 0; i < logins.len; i++) {
            if (strcmp(logins.items[i].name, c->name) == 0) {
                found = &logins.items[i];
                break;
            }
        }
        if (!found) {
            login_list_free(&logins);
            snprintf(err, err_n, "login %s not found", c->name);
            return false;
        }
        if (refresh_sync) {
            login_t fresh;
            if (!auth_fresh(found, &fresh, err, err_n)) {
                login_list_free(&logins);
                return false;
            }
            j_obj_set(out, "access", j_str(fresh.access));
            j_obj_set(out, "expires", j_int(fresh.expires));
            free(fresh.name);
            free(fresh.access);
            free(fresh.refresh);
            free(fresh.verifier);
        } else {
            j_obj_set(out, "access", j_str(found->access));
            j_obj_set(out, "expires", j_int(found->expires));
        }
        login_list_free(&logins);
        return true;
    }

    if (strcmp(c->kind, "oauth") == 0) {
        oa_tok_t tok;
        bool found = false;
        if (!oa_load(c->name, &tok, &found, err, err_n) || !found) {
            if (!found) snprintf(err, err_n, "oauth credential %s not found", c->name);
            return false;
        }
        int64_t now = now_ms();
        if (refresh_sync && !oa_fresh(&tok, now)) {
            oa_tok_t fresh;
            if (!oa_freshen_at(c->name, &tok, now + 60000, &fresh, err, err_n)) {
                oa_tok_free(&tok);
                return false;
            }
            j_obj_set(out, "access", j_str(fresh.access));
            j_obj_set(out, "expires", j_int(fresh.expires));
            oa_tok_free(&fresh);
        } else {
            j_obj_set(out, "access", j_str(tok.access));
            j_obj_set(out, "expires", j_int(tok.expires));
        }
        oa_tok_free(&tok);
        return true;
    }

    if (strcmp(c->kind, "api_key") == 0) {
        jval_t *entry = NULL;
        if (!ak_get(c->name, &entry, err, err_n)) return false;
        if (!entry) {
            snprintf(err, err_n, "api key %s not found", c->name);
            return false;
        }
        j_obj_set(out, "api_key", j_str(j_str_at(entry, "key")));
        j_free(entry);
        return true;
    }

    if (strcmp(c->kind, "acp") == 0) {
        char dir[1024];
        acp_dir(c->name, dir, sizeof(dir));
        j_obj_set(out, "acp_dir", j_str(dir));
        char em[256];
        if (acp_email(c->name, em, sizeof(em))) {
            j_obj_set(out, "email", j_str(em));
        }
        return true;
    }

    snprintf(err, err_n, "unknown credential kind %s", c->kind);
    return false;
}

static jval_t *build_status_or_list(bool include_holds, char *err, size_t err_n) {
    login_list_t logins;
    hold_list_t holds;
    unavail_list_t unavail;
    str_list_t order;
    jval_t *keys = NULL;

    if (!auth_load(&logins, err, err_n)) return NULL;
    if (!auth_holds(&holds, err, err_n)) {
        login_list_free(&logins);
        return NULL;
    }
    if (!auth_models(&unavail, err, err_n)) {
        login_list_free(&logins);
        hold_list_free(&holds);
        return NULL;
    }
    if (!auth_names(&order, err, err_n)) {
        login_list_free(&logins);
        hold_list_free(&holds);
        unavail_list_free(&unavail);
        return NULL;
    }
    if (!ak_read(&keys, err, err_n)) {
        login_list_free(&logins);
        hold_list_free(&holds);
        unavail_list_free(&unavail);
        str_list_free(&order);
        return NULL;
    }

    int64_t now = now_ms();
    jval_t *res = make_ok();
    j_obj_set(res, "now_ms", j_int(now));

    jval_t *arr = j_arr();
    login_list_t ranked;
    if (auth_rank(&order, &logins, &ranked, err, err_n)) {
        for (size_t i = 0; i < ranked.len; i++) {
            const login_t *l = &ranked.items[i];
            char id[256];
            auth_id_for_login(l->name, id, sizeof(id));
            char health[128];
            auth_health(id, &holds, now, health, sizeof(health));
            jval_t *item = j_obj();
            j_obj_set(item, "name", j_str(l->name));
            j_obj_set(item, "provider", j_str("anthropic"));
            j_obj_set(item, "kind", j_str("login"));
            j_obj_set(item, "id", j_str(id));
            j_obj_set(item, "expires", j_int(l->expires));
            j_obj_set(item, "health", j_str(health));
            j_arr_push(arr, item);
        }
        login_list_free(&ranked);
    }

    if (keys && keys->type == J_OBJ) {
        for (size_t i = 0; i < keys->obj_len; i++) {
            const char *name = keys->obj[i].key;
            const jval_t *entry = keys->obj[i].val;
            if (!entry || entry->type != J_OBJ) continue;
            const char *prov = ak_provider(name, entry);
            const char *type = j_str_at(entry, "type");
            if (!*type) type = "api_key";
            char id[256];
            auth_credential_id(prov, name, id, sizeof(id));
            char health[128];
            auth_health(id, &holds, now, health, sizeof(health));

            jval_t *item = j_obj();
            j_obj_set(item, "name", j_str(name));
            j_obj_set(item, "provider", j_str(prov));
            j_obj_set(item, "kind", j_str(type));
            j_obj_set(item, "id", j_str(id));
            j_obj_set(item, "health", j_str(health));
            if (strcmp(type, "api_key") == 0) {
                char masked[64];
                ak_mask(j_str_at(entry, "key"), masked, sizeof(masked));
                j_obj_set(item, "masked", j_str(masked));
            } else if (strcmp(type, "oauth") == 0) {
                int64_t exp = 0;
                j_int_at(entry, "expires", &exp);
                j_obj_set(item, "expires", j_int(exp));
            } else if (strcmp(type, "acp") == 0) {
                char note[256];
                acp_note(name, note, sizeof(note));
                j_obj_set(item, "note", j_str(note));
            }
            j_arr_push(arr, item);
        }
    }

    j_obj_set(res, "credentials", arr);
    j_obj_set(res, "count", j_int((int64_t)arr->arr_len));

    if (include_holds) {
        jval_t *harr = j_arr();
        for (size_t i = 0; i < holds.len; i++) {
            if (holds.items[i].until <= now) continue;
            jval_t *ho = j_obj();
            j_obj_set(ho, "id", j_str(holds.items[i].id));
            j_obj_set(ho, "model", j_str(holds.items[i].model));
            j_obj_set(ho, "until", j_int(holds.items[i].until));
            j_obj_set(ho, "remaining_ms", j_int(holds.items[i].until - now));
            j_arr_push(harr, ho);
        }
        j_obj_set(res, "holds", harr);

        jval_t *uarr = j_arr();
        for (size_t i = 0; i < unavail.len; i++) {
            jval_t *uo = j_obj();
            j_obj_set(uo, "id", j_str(unavail.items[i].id));
            j_obj_set(uo, "model", j_str(unavail.items[i].model));
            j_arr_push(uarr, uo);
        }
        j_obj_set(res, "unavailable", uarr);
    }

    j_free(keys);
    str_list_free(&order);
    unavail_list_free(&unavail);
    hold_list_free(&holds);
    login_list_free(&logins);
    return res;
}

static bool parse_routes_from_req(const jval_t *req, route_cand_t **out_routes, size_t *out_cnt, char *err, size_t err_n) {
    *out_routes = NULL;
    *out_cnt = 0;
    const char *op = j_str_at(req, "op");
    if (strcmp(op, "token") == 0) {
        const char *prov = j_str_at(req, "provider");
        const char *mod = j_str_at(req, "model");
        if (!prov[0]) {
            snprintf(err, err_n, "token requires provider");
            return false;
        }
        if (strlen(prov) >= sizeof(((route_cand_t *)0)->provider) ||
            strlen(mod) >= sizeof(((route_cand_t *)0)->model)) {
            snprintf(err, err_n, "route provider/model too long");
            return false;
        }
        route_cand_t *rc = calloc(1, sizeof(*rc));
        rc->rank = 0;
        snprintf(rc->provider, sizeof(rc->provider), "%s", prov);
        snprintf(rc->model, sizeof(rc->model), "%s", mod);
        *out_routes = rc;
        *out_cnt = 1;
        return true;
    }

    jval_t *rarr = j_obj_get(req, "routes");
    if (!rarr || rarr->type != J_ARR || rarr->arr_len == 0) {
        snprintf(err, err_n, "route requires non-empty routes array");
        return false;
    }
    route_cand_t *rcs = calloc(rarr->arr_len, sizeof(*rcs));
    for (size_t i = 0; i < rarr->arr_len; i++) {
        const jval_t *it = rarr->arr[i];
        if (!it || it->type != J_OBJ) {
            free(rcs);
            snprintf(err, err_n, "invalid route entry");
            return false;
        }
        const char *prov = j_str_at(it, "provider");
        const char *mod = j_str_at(it, "model");
        if (!prov[0]) {
            free(rcs);
            snprintf(err, err_n, "route entry missing provider");
            return false;
        }
        if (strlen(prov) >= sizeof(rcs[i].provider) ||
            strlen(mod) >= sizeof(rcs[i].model)) {
            free(rcs);
            snprintf(err, err_n, "route provider/model too long");
            return false;
        }
        int64_t rnk = (int64_t)i;
        j_int_at(it, "rank", &rnk);
        rcs[i].rank = rnk;
        snprintf(rcs[i].provider, sizeof(rcs[i].provider), "%s", prov);
        snprintf(rcs[i].model, sizeof(rcs[i].model), "%s", mod);
    }
    *out_routes = rcs;
    *out_cnt = rarr->arr_len;
    return true;
}

static bool eval_route_plan(const jval_t *req,
                            bool restricted,
                            policy_res_t *pres_out,
                            cred_t *selected_cred_out,
                            bool *has_cred_out,
                            char *err,
                            size_t err_n) {
    *has_cred_out = false;
    memset(selected_cred_out, 0, sizeof(*selected_cred_out));

    route_cand_t *routes = NULL;
    size_t route_cnt = 0;
    if (!parse_routes_from_req(req, &routes, &route_cnt, err, err_n)) return false;

    cred_list_t ordered_creds;
    hold_list_t holds;
    unavail_list_t unavail;

    if (!auth_routable_credentials(&ordered_creds, err, err_n)) {
        free(routes);
        return false;
    }
    if (!auth_holds(&holds, err, err_n)) {
        cred_list_free(&ordered_creds);
        free(routes);
        return false;
    }
    if (!auth_models(&unavail, err, err_n)) {
        hold_list_free(&holds);
        cred_list_free(&ordered_creds);
        free(routes);
        return false;
    }

    int64_t now = now_ms();
    int64_t req_now = 0;
    if (!restricted && j_int_at(req, "now_ms", &req_now) && req_now > 0) now = req_now;

    route_req_t rr;
    memset(&rr, 0, sizeof(rr));
    rr.now_ms = now;
    rr.routes = routes;
    rr.route_cnt = route_cnt;
    rr.exclude_provider = j_str_at(req, "exclude_provider");
    rr.prefer_id = j_str_at(req, "prefer");
    rr.top_id = j_str_at(req, "top");
    rr.rotate_from_id = j_str_at(req, "rotate_from");
    rr.pool = &ordered_creds;
    rr.holds = &holds;
    rr.unavail = &unavail;

    bool ok = policy_route(&rr, pres_out, err, err_n);
    if (ok && pres_out->has_selected) {
        for (size_t i = 0; i < ordered_creds.len; i++) {
            if (strcmp(ordered_creds.items[i].name, pres_out->selected_id) == 0 &&
                strcmp(ordered_creds.items[i].provider, pres_out->provider) == 0) {
                selected_cred_out->name = strdup(ordered_creds.items[i].name);
                selected_cred_out->provider = strdup(ordered_creds.items[i].provider);
                selected_cred_out->id = strdup(ordered_creds.items[i].id);
                selected_cred_out->kind = strdup(ordered_creds.items[i].kind);
                *has_cred_out = true;
                break;
            }
        }
    }

    unavail_list_free(&unavail);
    hold_list_free(&holds);
    cred_list_free(&ordered_creds);
    free(routes);
    return ok;
}

static void cred_single_free(cred_t *c) {
    free(c->name);
    free(c->provider);
    free(c->id);
    free(c->kind);
    memset(c, 0, sizeof(*c));
}

static jval_t *build_route_response(const policy_res_t *pres, const cred_t *cred, bool has_cred, bool refresh_sync, char *err, size_t err_n) {
    jval_t *res = make_ok();
    j_obj_set(res, "http_status", j_int(pres->http_status));
    j_obj_set(res, "retry_ms", j_int(pres->retry_ms));
    j_obj_set(res, "retry_s", j_int(pres->retry_s));
    j_obj_set(res, "primary_retry_ms", j_int(pres->primary_retry_ms));
    j_obj_set(res, "is_fallback", j_bool(pres->is_fallback));
    j_obj_set(res, "route_rank", j_int(pres->route_rank));
    j_obj_set(res, "ready_cnt", j_int(pres->ready_cnt));
    if (pres->has_selected && has_cred) {
        j_obj_set(res, "provider", j_str(pres->provider));
        j_obj_set(res, "model", j_str(pres->model));
        j_obj_set(res, "login_id", j_str(pres->selected_id));
        if (!fill_cred_secret(cred, res, refresh_sync, err, err_n)) {
            j_free(res);
            return NULL;
        }
    } else {
        j_obj_set(res, "provider", j_str(""));
        j_obj_set(res, "model", j_str(""));
        j_obj_set(res, "login_id", j_str(""));
    }
    return res;
}

static jval_t *exec_non_route_op(const jval_t *req, int64_t started_ms, bool bg_refresh) {
    const char *op = j_str_at(req, "op");
    char err[512];
    err[0] = '\0';

    if (strcmp(op, "ping") == 0) {
        jval_t *r = make_ok();
        j_obj_set(r, "pid", j_int((int64_t)getpid()));
        j_obj_set(r, "uptime_ms", j_int(started_ms > 0 ? (now_ms() - started_ms) : 0));
        j_obj_set(r, "bg_refresh", j_bool(bg_refresh));
        return r;
    }

    if (strcmp(op, "status") == 0) {
        jval_t *r = build_status_or_list(true, err, sizeof(err));
        return r ? r : make_err(err);
    }

    if (strcmp(op, "list") == 0) {
        jval_t *r = build_status_or_list(false, err, sizeof(err));
        return r ? r : make_err(err);
    }

    if (strcmp(op, "cool") == 0) {
        const char *id = j_str_at(req, "id");
        const char *model = j_str_at(req, "model");
        if (!id[0]) return make_err("cool requires id");
        int64_t status = 429;
        j_int_at(req, "status", &status);
        int64_t cooldown_ms = AUTH_COOLDOWN_MS;
        const char *dur = j_str_at(req, "duration");
        if (dur[0]) {
            if (!parse_duration_ms(dur, &cooldown_ms)) {
                return make_err("invalid cooldown duration");
            }
        } else {
            j_int_at(req, "cooldown_ms", &cooldown_ms);
        }
        bool limited = false;
        if (!auth_limit(id, model, (int)status, NULL, 0, cooldown_ms, &limited, err, sizeof(err))) {
            return make_err(err);
        }
        jval_t *r = make_ok();
        j_obj_set(r, "id", j_str(id));
        j_obj_set(r, "model", j_str(model));
        j_obj_set(r, "limited", j_bool(limited));
        j_obj_set(r, "cooldown_ms", j_int(cooldown_ms));
        return r;
    }

    if (strcmp(op, "add") == 0) {
        const char *prov = j_str_at(req, "provider");
        const char *name = j_str_at(req, "name");
        const char *key = j_str_at(req, "key");
        if (!prov[0]) return make_err("add requires provider");
        if (!name[0]) name = prov;
        if (!key[0]) return make_err("add requires key");
        if (!ak_set_named(prov, name, key, err, sizeof(err))) return make_err(err);
        char cid[256];
        auth_credential_id(prov, name, cid, sizeof(cid));
        auth_forget(cid, err, sizeof(err));
        jval_t *r = make_ok();
        j_obj_set(r, "name", j_str(name));
        j_obj_set(r, "provider", j_str(prov));
        j_obj_set(r, "id", j_str(cid));
        return r;
    }

    if (strcmp(op, "remove") == 0) {
        const char *name = j_str_at(req, "name");
        if (!name[0]) return make_err("remove requires name");
        bool is_l = false;
        if (!auth_is_login(name, &is_l, err, sizeof(err))) return make_err(err);
        if (is_l) {
            if (!auth_remove_login(name, err, sizeof(err))) return make_err(err);
            char cid[256];
            auth_id_for_login(name, cid, sizeof(cid));
            auth_forget(cid, err, sizeof(err));
        } else {
            jval_t *e = NULL;
            if (!ak_get(name, &e, err, sizeof(err))) return make_err(err);
            if (!e) return make_err("credential not found");
            char cid[256];
            auth_credential_id(ak_provider(name, e), name, cid, sizeof(cid));
            bool is_acp = acp_is(name, e);
            j_free(e);
            if (is_acp) acp_free(name, err, sizeof(err));
            if (!ak_remove(name, err, sizeof(err))) return make_err(err);
            auth_forget(cid, err, sizeof(err));
        }
        str_list_t ord = {0};
        if (auth_names(&ord, err, sizeof(err)) && ord.len > 0) {
            str_list_t kept = {0};
            for (size_t i = 0; i < ord.len; i++) {
                if (strcmp(ord.items[i], name) != 0) str_list_push(&kept, ord.items[i]);
            }
            auth_write_names(&kept, err, sizeof(err));
            str_list_free(&kept);
            str_list_free(&ord);
        }
        jval_t *r = make_ok();
        j_obj_set(r, "removed", j_str(name));
        return r;
    }

    if (strcmp(op, "order") == 0 || strcmp(op, "top") == 0) {
        cred_list_t all = {0};
        if (!auth_credentials(&all, err, sizeof(err))) return make_err(err);
        str_list_t known = {0};
        for (size_t i = 0; i < all.len; i++) {
            str_list_push(&known, all.items[i].name);
        }
        cred_list_free(&all);

        jval_t *names_arr = j_obj_get(req, "names");
        str_list_t names = {0};
        if (strcmp(op, "top") == 0) {
            const char *n = j_str_at(req, "name");
            if (!n[0] || strchr(n, '\n') || strchr(n, '\r') || !str_list_has(&known, n)) {
                str_list_free(&known);
                return make_err("top requires a known credential name");
            }
            str_list_push(&names, n);
        } else {
            if (!names_arr || names_arr->type != J_ARR || names_arr->arr_len == 0) {
                str_list_free(&known);
                return make_err("order requires names array");
            }
            for (size_t i = 0; i < names_arr->arr_len; i++) {
                const jval_t *item = names_arr->arr[i];
                if (!item || item->type != J_STR || !item->s[0] ||
                    strchr(item->s, '\n') || strchr(item->s, '\r')) {
                    str_list_free(&names);
                    str_list_free(&known);
                    return make_err("order contains invalid credential name");
                }
                if (!str_list_has(&known, item->s)) {
                    snprintf(err, sizeof(err), "unknown credential name: %s", item->s);
                    str_list_free(&names);
                    str_list_free(&known);
                    return make_err(err);
                }
                if (str_list_has(&names, item->s)) {
                    snprintf(err, sizeof(err), "duplicate credential name: %s", item->s);
                    str_list_free(&names);
                    str_list_free(&known);
                    return make_err(err);
                }
                str_list_push(&names, item->s);
            }
        }
        str_list_t cur = {0};
        if (auth_names(&cur, err, sizeof(err))) {
            for (size_t i = 0; i < cur.len; i++) {
                if (str_list_has(&known, cur.items[i]) && !str_list_has(&names, cur.items[i])) {
                    str_list_push(&names, cur.items[i]);
                }
            }
            str_list_free(&cur);
        }
        str_list_free(&known);
        bool ok = auth_write_names(&names, err, sizeof(err));
        str_list_free(&names);
        if (!ok) return make_err(err);
        return make_ok();
    }

    if (strcmp(op, "rotate") == 0) {
        const char *prov = j_str_at(req, "provider");
        cred_list_t all = {0};
        str_list_t cur = {0};
        cred_list_t picked = {0};
        if (!auth_credentials(&all, err, sizeof(err))) return make_err(err);
        if (!auth_names(&cur, err, sizeof(err))) {
            cred_list_free(&all);
            return make_err(err);
        }
        if (!auth_credential_pick(&cur, &all, &picked, err, sizeof(err))) {
            str_list_free(&cur);
            cred_list_free(&all);
            return make_err(err);
        }
        str_list_t next_order = {0};
        const char *first_match = NULL;
        for (size_t i = 0; i < picked.len; i++) {
            if (prov[0] && strcmp(picked.items[i].provider, prov) != 0) {
                str_list_push(&next_order, picked.items[i].name);
            } else if (!first_match) {
                first_match = picked.items[i].name;
            } else {
                str_list_push(&next_order, picked.items[i].name);
            }
        }
        if (first_match) str_list_push(&next_order, first_match);
        bool ok = auth_write_names(&next_order, err, sizeof(err));
        jval_t *r = ok ? make_ok() : make_err(err);
        if (ok && first_match) j_obj_set(r, "rotated", j_str(first_match));
        str_list_free(&next_order);
        cred_list_free(&picked);
        str_list_free(&cur);
        cred_list_free(&all);
        return r;
    }

    if (strcmp(op, "forget") == 0) {
        const char *id = j_str_at(req, "id");
        if (!id[0]) return make_err("forget requires id");
        if (!auth_forget(id, err, sizeof(err))) return make_err(err);
        return make_ok();
    }

    if (strcmp(op, "unavail") == 0) {
        const char *id = j_str_at(req, "id");
        const char *model = j_str_at(req, "model");
        if (!id[0] || !model[0]) return make_err("unavail requires id and model");
        if (!auth_model_update(id, model, true, err, sizeof(err))) {
            return make_err(err);
        }
        jval_t *r = make_ok();
        j_obj_set(r, "marked", j_bool(true));
        return r;
    }

    if (strcmp(op, "export") == 0) {
        login_list_t logins = {0};
        jval_t *keys = NULL;
        if (!auth_load(&logins, err, sizeof(err))) return make_err(err);
        if (!ak_read(&keys, err, sizeof(err))) {
            login_list_free(&logins);
            return make_err(err);
        }
        jval_t *r = make_ok();
        jval_t *larr = j_arr();
        for (size_t i = 0; i < logins.len; i++) {
            jval_t *lo = j_obj();
            j_obj_set(lo, "name", j_str(logins.items[i].name));
            j_obj_set(lo, "access", j_str(logins.items[i].access));
            j_obj_set(lo, "refresh", j_str(logins.items[i].refresh));
            j_obj_set(lo, "expires", j_int(logins.items[i].expires));
            j_arr_push(larr, lo);
        }
        j_obj_set(r, "logins", larr);
        j_obj_set(r, "keys", keys ? keys : j_obj());
        login_list_free(&logins);
        return r;
    }

    return make_err("unknown op");
}

jval_t *router_exec_direct(const jval_t *req, bool restricted) {
    if (!req || req->type != J_OBJ) return make_err("request must be a JSON object");
    jval_t *ver = j_obj_get(req, "v");
    if (!ver || ver->type != J_INT || ver->i != AUTH_ROUTER_WIRE_VERSION) {
        return make_err("unsupported wire version");
    }
    const char *op = j_str_at(req, "op");
    if (!op[0]) return make_err("missing op");
    if (restricted && !op_allowed_restricted(op)) {
        return make_err("restricted socket: operation not permitted");
    }

    char lock_path[1088];
    char err[512];
    err[0] = '\0';
    state_path("/router.lock", lock_path, sizeof(lock_path));
    int lfd = -1;
    if (!file_lock(lock_path, &lfd, err, sizeof(err))) {
        return make_err(err);
    }

    jval_t *res = NULL;
    if (strcmp(op, "token") == 0 || strcmp(op, "route") == 0) {
        policy_res_t pres;
        cred_t cred;
        bool has_cred = false;
        bool plan_ok = eval_route_plan(req, restricted, &pres, &cred, &has_cred, err, sizeof(err));
        file_unlock(lfd);
        if (!plan_ok) {
            return make_err(err);
        }
        res = build_route_response(&pres, &cred, has_cred, true, err, sizeof(err));
        if (!res) res = make_err(err);
        cred_single_free(&cred);
        return res;
    }
    res = exec_non_route_op(req, 0, false);
    file_unlock(lfd);
    return res;
}

typedef struct {
    int fd;
    uint64_t conn_id;
    bool restricted;
    bool eof_read;
    int64_t last_activity_ms;
    sb_t inbuf;
    sb_t outbuf;
    size_t out_off;
    bool waiting_refresh;
} client_t;

typedef struct {
    int client_idx;
    uint64_t conn_id;
    policy_res_t pres;
    cred_t cred;
} refresh_waiter_t;

typedef struct {
    bool active;
    char kind[32];
    char name[128];
    pid_t pid;
    int pipe_fd;
    sb_t result_buf;
    refresh_waiter_t waiters[MAX_WAITERS];
    size_t waiter_cnt;
} refresh_job_t;

static void client_close(client_t *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->conn_id = 0;
    c->restricted = false;
    c->eof_read = false;
    c->last_activity_ms = 0;
    c->waiting_refresh = false;
    c->out_off = 0;
    sb_free(&c->inbuf);
    sb_free(&c->outbuf);
}

static void client_queue_json(client_t *c, const jval_t *v) {
    if (c->fd < 0) return;
    char *s = j_show(v);
    if (s) {
        size_t slen = strlen(s);
        if (c->outbuf.len + slen + 1 > MAX_OUTBUF_BYTES) {
            free(s);
            client_close(c);
            return;
        }
        sb_putn(&c->outbuf, s, slen);
        sb_putc(&c->outbuf, '\n');
        free(s);
    }
}

static void close_inherited_fds_except(int keep_fd) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            int fd = atoi(de->d_name);
            if (fd > 2 && fd != keep_fd && fd != dfd) {
                close(fd);
            }
        }
        closedir(d);
        return;
    }
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
    for (int fd = 3; fd < (int)max_fd; fd++) {
        if (fd != keep_fd) close(fd);
    }
}

static int find_job(refresh_job_t *jobs, const char *kind, const char *name) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].active && strcmp(jobs[i].kind, kind) == 0 && strcmp(jobs[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int start_refresh_job(refresh_job_t *jobs, const char *kind, const char *name, int64_t lead_ms, char *err, size_t err_n) {
    int slot = -1;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!jobs[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        snprintf(err, err_n, "too many concurrent refreshes");
        return -1;
    }

    int pfd[2];
    if (pipe(pfd) != 0) {
        snprintf(err, err_n, "pipe: %s", strerror(errno));
        return -1;
    }
    set_cloexec(pfd[0]);
    set_cloexec(pfd[1]);

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        snprintf(err, err_n, "fork: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        close_inherited_fds_except(pfd[1]);
        jval_t *out = j_obj();
        char werr[512];
        werr[0] = '\0';
        bool ok = false;

        if (strcmp(kind, "login") == 0) {
            login_list_t logins = {0};
            if (auth_load(&logins, werr, sizeof(werr))) {
                for (size_t i = 0; i < logins.len; i++) {
                    if (strcmp(logins.items[i].name, name) == 0) {
                        login_t fresh;
                        if (auth_fresh(&logins.items[i], &fresh, werr, sizeof(werr))) {
                            j_obj_set(out, "ok", j_bool(true));
                            j_obj_set(out, "access", j_str(fresh.access));
                            j_obj_set(out, "expires", j_int(fresh.expires));
                            free(fresh.name);
                            free(fresh.access);
                            free(fresh.refresh);
                            free(fresh.verifier);
                            ok = true;
                        }
                        break;
                    }
                }
                login_list_free(&logins);
            }
        } else if (strcmp(kind, "oauth") == 0) {
            oa_tok_t tok;
            bool found = false;
            if (oa_load(name, &tok, &found, werr, sizeof(werr)) && found) {
                oa_tok_t fresh;
                int64_t margin = lead_ms > 60000 ? lead_ms : 60000;
                if (oa_freshen_at(name, &tok, now_ms() + margin, &fresh, werr, sizeof(werr))) {
                    j_obj_set(out, "ok", j_bool(true));
                    j_obj_set(out, "access", j_str(fresh.access));
                    j_obj_set(out, "expires", j_int(fresh.expires));
                    oa_tok_free(&fresh);
                    ok = true;
                }
                oa_tok_free(&tok);
            }
        }

        if (!ok) {
            j_obj_set(out, "ok", j_bool(false));
            j_obj_set(out, "error", j_str(werr[0] ? werr : "refresh failed"));
        }

        char *s = j_show(out);
        if (s) {
            size_t len = strlen(s);
            size_t off = 0;
            while (off < len) {
                ssize_t w = write(pfd[1], s + off, len - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            free(s);
        }
        j_free(out);
        close(pfd[1]);
        _exit(0);
    }

    close(pfd[1]);
    int fl = fcntl(pfd[0], F_GETFL, 0);
    if (fl >= 0) fcntl(pfd[0], F_SETFL, fl | O_NONBLOCK);

    refresh_job_t *j = &jobs[slot];
    memset(j, 0, sizeof(*j));
    j->active = true;
    snprintf(j->kind, sizeof(j->kind), "%s", kind);
    snprintf(j->name, sizeof(j->name), "%s", name);
    j->pid = pid;
    j->pipe_fd = pfd[0];
    sb_init(&j->result_buf);
    return slot;
}

static void drain_client_inbuf(client_t *clients,
                               int cidx,
                               refresh_job_t *jobs,
                               int64_t started_ms,
                               bool bg_refresh);

static void finish_refresh_job(refresh_job_t *job,
                               refresh_job_t *jobs,
                               client_t *clients,
                               int64_t started_ms,
                               bool bg_refresh) {
    close(job->pipe_fd);
    job->pipe_fd = -1;
    int st = 0;
    waitpid(job->pid, &st, 0);

    jval_t *parsed = j_parse(job->result_buf.data ? job->result_buf.data : "");
    bool ok = parsed && parsed->type == J_OBJ && j_obj_get(parsed, "ok") && j_obj_get(parsed, "ok")->b;
    const char *access = ok ? j_str_at(parsed, "access") : "";
    int64_t expires = 0;
    if (ok) j_int_at(parsed, "expires", &expires);
    const char *rerr = (!ok && parsed) ? j_str_at(parsed, "error") : "refresh worker failed";

    int drain_idx[MAX_WAITERS];
    uint64_t drain_conn[MAX_WAITERS];
    size_t drain_cnt = 0;
    int64_t done_now = now_ms();

    for (size_t i = 0; i < job->waiter_cnt; i++) {
        refresh_waiter_t *w = &job->waiters[i];
        if (w->client_idx >= 0 && w->client_idx < MAX_CLIENTS &&
            clients[w->client_idx].fd >= 0 &&
            clients[w->client_idx].conn_id == w->conn_id) {
            client_t *c = &clients[w->client_idx];
            c->waiting_refresh = false;
            c->last_activity_ms = done_now;
            if (ok) {
                jval_t *res = make_ok();
                j_obj_set(res, "http_status", j_int(w->pres.http_status));
                j_obj_set(res, "retry_ms", j_int(0));
                j_obj_set(res, "retry_s", j_int(0));
                j_obj_set(res, "primary_retry_ms", j_int(w->pres.primary_retry_ms));
                j_obj_set(res, "is_fallback", j_bool(w->pres.is_fallback));
                j_obj_set(res, "route_rank", j_int(w->pres.route_rank));
                j_obj_set(res, "ready_cnt", j_int(w->pres.ready_cnt));
                j_obj_set(res, "provider", j_str(w->pres.provider));
                j_obj_set(res, "model", j_str(w->pres.model));
                j_obj_set(res, "login_id", j_str(w->pres.selected_id));
                j_obj_set(res, "kind", j_str(w->cred.kind));
                j_obj_set(res, "credential_id", j_str(w->cred.id));
                j_obj_set(res, "access", j_str(access));
                j_obj_set(res, "expires", j_int(expires));
                client_queue_json(c, res);
                j_free(res);
            } else {
                jval_t *er = make_err(rerr);
                client_queue_json(c, er);
                j_free(er);
            }
            if (c->fd >= 0 && drain_cnt < MAX_WAITERS) {
                drain_idx[drain_cnt] = w->client_idx;
                drain_conn[drain_cnt] = w->conn_id;
                drain_cnt++;
            }
        }
        cred_single_free(&w->cred);
    }

    j_free(parsed);
    sb_free(&job->result_buf);
    job->active = false;
    job->waiter_cnt = 0;

    for (size_t i = 0; i < drain_cnt; i++) {
        int cidx = drain_idx[i];
        if (clients[cidx].fd >= 0 &&
            clients[cidx].conn_id == drain_conn[i] &&
            !clients[cidx].waiting_refresh) {
            drain_client_inbuf(clients, cidx, jobs, started_ms, bg_refresh);
        }
    }
}

static void trigger_bg_refreshes(refresh_job_t *jobs, int64_t lead_ms) {
    int64_t now = now_ms();
    char err[256];
    login_list_t logins = {0};
    if (auth_load(&logins, err, sizeof(err))) {
        for (size_t i = 0; i < logins.len; i++) {
            const login_t *l = &logins.items[i];
            if (!l->refresh[0]) continue;
            if (l->expires > 0 && l->expires - now <= lead_ms) {
                if (find_job(jobs, "login", l->name) < 0) {
                    start_refresh_job(jobs, "login", l->name, lead_ms, err, sizeof(err));
                }
            }
        }
        login_list_free(&logins);
    }
    jval_t *keys = NULL;
    if (ak_read(&keys, err, sizeof(err)) && keys && keys->type == J_OBJ) {
        for (size_t i = 0; i < keys->obj_len; i++) {
            const char *name = keys->obj[i].key;
            const jval_t *e = keys->obj[i].val;
            if (!e || e->type != J_OBJ) continue;
            if (strcmp(j_str_at(e, "type"), "oauth") != 0) continue;
            if (!j_str_at(e, "refresh")[0]) continue;
            int64_t exp = 0;
            j_int_at(e, "expires", &exp);
            if (exp > 0 && exp - now <= lead_ms) {
                if (find_job(jobs, "oauth", name) < 0) {
                    start_refresh_job(jobs, "oauth", name, lead_ms, err, sizeof(err));
                }
            }
        }
        j_free(keys);
    }
}

static int open_unix_listener(const char *path, mode_t sock_mode, char *err, size_t err_n) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        snprintf(err, err_n, "socket path too long: %s", path);
        return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    mode_t m = sock_mode ? sock_mode : 0600;
    mode_t dir_mode = (m & 0077) ? 0755 : 0700;

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        ensure_dir(dir, dir_mode);
    }

    struct stat st;
    if (lstat(path, &st) == 0) {
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe >= 0) {
            set_cloexec(probe);
            if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                close(probe);
                snprintf(err, err_n, "daemon already running on %s", path);
                return -1;
            }
            close(probe);
        }
        unlink(path);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, err_n, "socket: %s", strerror(errno));
        return -1;
    }
    set_cloexec(fd);
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    mode_t old_mask = umask(0077);
    int brc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_mask);
    if (brc != 0) {
        snprintf(err, err_n, "bind %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    chmod(path, m);
    if (listen(fd, 32) != 0) {
        snprintf(err, err_n, "listen %s: %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

static void handle_client_line(client_t *clients,
                               int cidx,
                               const char *line,
                               refresh_job_t *jobs,
                               int64_t started_ms,
                               bool bg_refresh) {
    client_t *c = &clients[cidx];
    jval_t *req = j_parse(line);
    if (!req || req->type != J_OBJ) {
        j_free(req);
        jval_t *er = make_err("invalid JSON request");
        client_queue_json(c, er);
        j_free(er);
        return;
    }

    jval_t *ver = j_obj_get(req, "v");
    if (!ver || ver->type != J_INT || ver->i != AUTH_ROUTER_WIRE_VERSION) {
        j_free(req);
        jval_t *er = make_err("unsupported wire version");
        client_queue_json(c, er);
        j_free(er);
        return;
    }

    const char *op = j_str_at(req, "op");
    if (!op[0]) {
        j_free(req);
        jval_t *er = make_err("missing op");
        client_queue_json(c, er);
        j_free(er);
        return;
    }

    if (c->restricted && !op_allowed_restricted(op)) {
        j_free(req);
        jval_t *er = make_err("restricted socket: operation not permitted");
        client_queue_json(c, er);
        j_free(er);
        return;
    }

    if (strcmp(op, "token") == 0 || strcmp(op, "route") == 0) {
        policy_res_t pres;
        cred_t cred;
        bool has_cred = false;
        char err[512];
        err[0] = '\0';
        if (!eval_route_plan(req, c->restricted, &pres, &cred, &has_cred, err, sizeof(err))) {
            jval_t *er = make_err(err);
            client_queue_json(c, er);
            j_free(er);
            j_free(req);
            return;
        }
        if (pres.has_selected && has_cred &&
            (strcmp(cred.kind, "login") == 0 || strcmp(cred.kind, "oauth") == 0) &&
            cred_needs_refresh(&cred, now_ms(), 60000, err, sizeof(err))) {
            int jidx = find_job(jobs, cred.kind, cred.name);
            if (jidx < 0) {
                jidx = start_refresh_job(jobs, cred.kind, cred.name, 60000, err, sizeof(err));
            }
            if (jidx >= 0 && jobs[jidx].waiter_cnt < MAX_WAITERS) {
                refresh_waiter_t *w = &jobs[jidx].waiters[jobs[jidx].waiter_cnt++];
                w->client_idx = cidx;
                w->conn_id = c->conn_id;
                w->pres = pres;
                w->cred = cred;
                c->waiting_refresh = true;
                j_free(req);
                return;
            }
            cred_single_free(&cred);
            jval_t *er = make_err(err[0] ? err : "failed to start refresh");
            client_queue_json(c, er);
            j_free(er);
            j_free(req);
            return;
        }

        jval_t *res = build_route_response(&pres, &cred, has_cred, false, err, sizeof(err));
        cred_single_free(&cred);
        if (!res) res = make_err(err);
        client_queue_json(c, res);
        j_free(res);
        j_free(req);
        return;
    }

    jval_t *res = exec_non_route_op(req, started_ms, bg_refresh);
    client_queue_json(c, res);
    j_free(res);
    j_free(req);
}

static void drain_client_inbuf(client_t *clients,
                               int cidx,
                               refresh_job_t *jobs,
                               int64_t started_ms,
                               bool bg_refresh) {
    client_t *c = &clients[cidx];
    char *nl = NULL;
    while (c->fd >= 0 && !c->waiting_refresh && c->inbuf.data &&
           (nl = memchr(c->inbuf.data, '\n', c->inbuf.len)) != NULL) {
        size_t llen = (size_t)(nl - c->inbuf.data);
        char *line = malloc(llen + 1);
        if (!line) {
            client_close(c);
            return;
        }
        memcpy(line, c->inbuf.data, llen);
        line[llen] = '\0';
        size_t rem = c->inbuf.len - (llen + 1);
        if (rem > 0) memmove(c->inbuf.data, nl + 1, rem);
        c->inbuf.len = rem;
        c->inbuf.data[rem] = '\0';
        handle_client_line(clients, cidx, line, jobs, started_ms, bg_refresh);
        free(line);
    }
}

int daemon_run(const daemon_cfg_t *cfg, char *err, size_t err_n) {
    if (cfg->state_dir_path && cfg->state_dir_path[0]) {
        state_dir_set_override(cfg->state_dir_path);
    }

    char sdir[1024];
    state_dir(sdir, sizeof(sdir));
    if (!ensure_dir(sdir, 0700)) {
        snprintf(err, err_n, "failed to create state dir %s", sdir);
        return 1;
    }

    char lock_path[1088];
    state_path("/daemon.lock", lock_path, sizeof(lock_path));
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0) {
        snprintf(err, err_n, "open %s: %s", lock_path, strerror(errno));
        return 1;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        snprintf(err, err_n, "another daemon already holds %s", lock_path);
        close(lock_fd);
        return 1;
    }

    char sock_path[512];
    if (cfg->socket_path && cfg->socket_path[0]) {
        snprintf(sock_path, sizeof(sock_path), "%s", cfg->socket_path);
    } else {
        daemon_default_socket(sock_path, sizeof(sock_path));
    }

    int primary_fd = open_unix_listener(sock_path, 0600, err, err_n);
    if (primary_fd < 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return 1;
    }

    int restricted_fd = -1;
    char rsock_path[512];
    rsock_path[0] = '\0';
    const char *rpath = (cfg->restricted_socket_path && cfg->restricted_socket_path[0])
                            ? cfg->restricted_socket_path
                            : getenv("AUTH_ROUTER_RESTRICTED_SOCKET");
    if (rpath && *rpath) {
        snprintf(rsock_path, sizeof(rsock_path), "%s", rpath);
        mode_t rmode = cfg->restricted_mode ? cfg->restricted_mode : 0600;
        restricted_fd = open_unix_listener(rsock_path, rmode, err, err_n);
        if (restricted_fd < 0) {
            close(primary_fd);
            unlink(sock_path);
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
            return 1;
        }
    }

    g_stop = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    client_t clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof(clients[i]));
        clients[i].fd = -1;
    }

    refresh_job_t jobs[MAX_JOBS];
    memset(jobs, 0, sizeof(jobs));
    for (int i = 0; i < MAX_JOBS; i++) jobs[i].pipe_fd = -1;

    int64_t started_ms = now_ms();
    int64_t bg_check_ms = 5000;
    int64_t bg_lead_ms = 120000;
    const char *env_chk = getenv("AUTH_ROUTER_BG_CHECK_MS");
    if (env_chk && *env_chk) str_to_i64(env_chk, &bg_check_ms);
    const char *env_lead = getenv("AUTH_ROUTER_BG_LEAD_MS");
    if (env_lead && *env_lead) str_to_i64(env_lead, &bg_lead_ms);
    int64_t idle_timeout_ms = CLIENT_IDLE_TIMEOUT_MS;
    const char *env_idle = getenv("AUTH_ROUTER_CLIENT_IDLE_MS");
    if (env_idle && *env_idle) str_to_i64(env_idle, &idle_timeout_ms);
    int64_t last_bg = started_ms;
    uint64_t next_conn_id = 1;

    while (!g_stop) {
        int64_t loop_now = now_ms();
        struct pollfd pfds[2 + MAX_CLIENTS + MAX_JOBS];
        int pmap_kind[2 + MAX_CLIENTS + MAX_JOBS];
        int pmap_idx[2 + MAX_CLIENTS + MAX_JOBS];
        nfds_t nfds = 0;

        pfds[nfds].fd = primary_fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        pmap_kind[nfds] = 0;
        pmap_idx[nfds] = 0;
        nfds++;

        if (restricted_fd >= 0) {
            pfds[nfds].fd = restricted_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            pmap_kind[nfds] = 1;
            pmap_idx[nfds] = 0;
            nfds++;
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd < 0) continue;
            if (clients[i].eof_read && !clients[i].waiting_refresh && clients[i].out_off >= clients[i].outbuf.len) {
                client_close(&clients[i]);
                continue;
            }
            if (idle_timeout_ms > 0 && !clients[i].waiting_refresh &&
                loop_now - clients[i].last_activity_ms > idle_timeout_ms) {
                client_close(&clients[i]);
                continue;
            }
            pfds[nfds].fd = clients[i].fd;
            pfds[nfds].events = 0;
            if (!clients[i].eof_read) pfds[nfds].events |= POLLIN;
            if (clients[i].out_off < clients[i].outbuf.len) pfds[nfds].events |= POLLOUT;
            pfds[nfds].revents = 0;
            pmap_kind[nfds] = 2;
            pmap_idx[nfds] = i;
            nfds++;
        }

        for (int i = 0; i < MAX_JOBS; i++) {
            if (!jobs[i].active || jobs[i].pipe_fd < 0) continue;
            pfds[nfds].fd = jobs[i].pipe_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            pmap_kind[nfds] = 3;
            pmap_idx[nfds] = i;
            nfds++;
        }

        int pr = poll(pfds, nfds, 250);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (nfds_t k = 0; k < nfds; k++) {
            if (!pfds[k].revents) continue;
            int kind = pmap_kind[k];
            int idx = pmap_idx[k];

            if (kind == 0 || kind == 1) {
                int lfd = (kind == 0) ? primary_fd : restricted_fd;
                for (;;) {
                    int cfd = accept(lfd, NULL, NULL);
                    if (cfd < 0) break;
                    set_cloexec(cfd);
                    int fl = fcntl(cfd, F_GETFL, 0);
                    if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                    int slot = -1;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (clients[i].fd < 0) {
                            slot = i;
                            break;
                        }
                    }
                    if (slot < 0) {
                        close(cfd);
                        continue;
                    }
                    clients[slot].fd = cfd;
                    clients[slot].conn_id = next_conn_id++;
                    clients[slot].restricted = (kind == 1);
                    clients[slot].eof_read = false;
                    clients[slot].last_activity_ms = now_ms();
                    clients[slot].waiting_refresh = false;
                    clients[slot].out_off = 0;
                    sb_init(&clients[slot].inbuf);
                    sb_init(&clients[slot].outbuf);
                }
            } else if (kind == 2) {
                client_t *c = &clients[idx];
                if (c->fd < 0) continue;
                if (pfds[k].revents & (POLLERR | POLLNVAL)) {
                    client_close(c);
                    continue;
                }
                if ((pfds[k].revents & POLLHUP) && !(pfds[k].revents & POLLIN)) {
                    client_close(c);
                    continue;
                }
                if (pfds[k].revents & POLLIN) {
                    char buf[4096];
                    ssize_t r = read(c->fd, buf, sizeof(buf));
                    if (r > 0) {
                        c->last_activity_ms = now_ms();
                        if (c->inbuf.len + (size_t)r > MAX_INBUF_BYTES) {
                            client_close(c);
                            continue;
                        }
                        sb_putn(&c->inbuf, buf, (size_t)r);
                        drain_client_inbuf(clients, idx, jobs, started_ms, !cfg->no_bg_refresh);
                    } else if (r == 0) {
                        c->eof_read = true;
                        if (!c->waiting_refresh && c->out_off >= c->outbuf.len) {
                            client_close(c);
                            continue;
                        }
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        client_close(c);
                        continue;
                    }
                }
                if (c->fd >= 0 && (pfds[k].revents & POLLOUT) && c->out_off < c->outbuf.len) {
                    ssize_t w = write(c->fd, c->outbuf.data + c->out_off, c->outbuf.len - c->out_off);
                    if (w > 0) {
                        c->last_activity_ms = now_ms();
                        c->out_off += (size_t)w;
                        if (c->out_off >= c->outbuf.len) {
                            c->outbuf.len = 0;
                            c->out_off = 0;
                            if (c->outbuf.data) c->outbuf.data[0] = '\0';
                            if (c->eof_read && !c->waiting_refresh) {
                                client_close(c);
                            }
                        }
                    } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        client_close(c);
                    }
                }
            } else if (kind == 3) {
                refresh_job_t *j = &jobs[idx];
                if (!j->active || j->pipe_fd < 0) continue;
                char buf[4096];
                bool done = false;
                for (;;) {
                    ssize_t r = read(j->pipe_fd, buf, sizeof(buf));
                    if (r > 0) {
                        if (j->result_buf.len + (size_t)r > MAX_JOB_RESULT_BYTES) {
                            sb_free(&j->result_buf);
                            done = true;
                            break;
                        }
                        sb_putn(&j->result_buf, buf, (size_t)r);
                        continue;
                    }
                    if (r == 0) {
                        done = true;
                        break;
                    }
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    done = true;
                    break;
                }
                if (done || (pfds[k].revents & (POLLHUP | POLLERR))) {
                    finish_refresh_job(j, jobs, clients, started_ms, !cfg->no_bg_refresh);
                }
            }
        }

        if (!cfg->no_bg_refresh) {
            int64_t now = now_ms();
            if (now - last_bg >= bg_check_ms) {
                last_bg = now;
                trigger_bg_refreshes(jobs, bg_lead_ms);
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd >= 0) client_close(&clients[i]);
    }
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].active) {
            if (jobs[i].pipe_fd >= 0) {
                close(jobs[i].pipe_fd);
                jobs[i].pipe_fd = -1;
            }
            if (jobs[i].pid > 0) kill(jobs[i].pid, SIGTERM);
        }
    }
    int64_t reap_deadline = now_ms() + 1000;
    for (;;) {
        bool any_alive = false;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (jobs[i].active && jobs[i].pid > 0) {
                int st = 0;
                pid_t wp = waitpid(jobs[i].pid, &st, WNOHANG);
                if (wp == jobs[i].pid || (wp < 0 && errno == ECHILD)) {
                    jobs[i].pid = -1;
                } else {
                    any_alive = true;
                }
            }
        }
        if (!any_alive || now_ms() >= reap_deadline) break;
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 20000000;
        nanosleep(&ts, NULL);
    }
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].active) {
            if (jobs[i].pid > 0) {
                kill(jobs[i].pid, SIGKILL);
                int st = 0;
                waitpid(jobs[i].pid, &st, 0);
                jobs[i].pid = -1;
            }
            for (size_t w = 0; w < jobs[i].waiter_cnt; w++) {
                cred_single_free(&jobs[i].waiters[w].cred);
            }
            sb_free(&jobs[i].result_buf);
            jobs[i].active = false;
        }
    }

    close(primary_fd);
    unlink(sock_path);
    if (restricted_fd >= 0) {
        close(restricted_fd);
        unlink(rsock_path);
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return 0;
}

daemon_rpc_status_t daemon_rpc(const char *sock_path,
                               const jval_t *req,
                               int64_t timeout_ms,
                               jval_t **resp_out,
                               char *err,
                               size_t err_n) {
    *resp_out = NULL;
    char path_buf[512];
    if (!sock_path || !sock_path[0]) {
        daemon_default_socket(path_buf, sizeof(path_buf));
        sock_path = path_buf;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        snprintf(err, err_n, "socket path too long");
        return DAEMON_RPC_ERR;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, err_n, "socket: %s", strerror(errno));
        return DAEMON_RPC_ERR;
    }
    set_cloexec(fd);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int e = errno;
        close(fd);
        if (e == ENOENT || e == ECONNREFUSED) {
            snprintf(err, err_n, "daemon unavailable at %s", sock_path);
            return DAEMON_RPC_UNAVAILABLE;
        }
        snprintf(err, err_n, "connect %s: %s", sock_path, strerror(e));
        return DAEMON_RPC_ERR;
    }

    char *wire = j_show(req);
    sb_t out;
    sb_init(&out);
    sb_puts(&out, wire);
    sb_putc(&out, '\n');
    free(wire);

    size_t off = 0;
    while (off < out.len) {
        ssize_t w = send(fd, out.data + off, out.len - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        snprintf(err, err_n, "daemon write failed: %s", strerror(errno));
        sb_free(&out);
        close(fd);
        return DAEMON_RPC_ERR;
    }
    sb_free(&out);

    int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 15000);
    sb_t in;
    sb_init(&in);
    for (;;) {
        int64_t rem = deadline - now_ms();
        if (rem <= 0) {
            snprintf(err, err_n, "daemon response timeout");
            sb_free(&in);
            close(fd);
            return DAEMON_RPC_ERR;
        }
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, (int)(rem > 1000 ? 1000 : rem));
        if (pr < 0) {
            if (errno == EINTR) continue;
            snprintf(err, err_n, "poll: %s", strerror(errno));
            sb_free(&in);
            close(fd);
            return DAEMON_RPC_ERR;
        }
        if (pr == 0) continue;
        char buf[4096];
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r > 0) {
            if (in.len + (size_t)r > MAX_OUTBUF_BYTES) {
                snprintf(err, err_n, "daemon response exceeds maximum size");
                sb_free(&in);
                close(fd);
                return DAEMON_RPC_ERR;
            }
            sb_putn(&in, buf, (size_t)r);
            if (memchr(in.data, '\n', in.len) != NULL) break;
        } else if (r == 0) {
            break;
        } else if (errno != EINTR) {
            snprintf(err, err_n, "daemon read failed: %s", strerror(errno));
            sb_free(&in);
            close(fd);
            return DAEMON_RPC_ERR;
        }
    }
    close(fd);

    char *nl = in.data ? memchr(in.data, '\n', in.len) : NULL;
    if (nl) *nl = '\0';
    jval_t *parsed = j_parse(in.data ? in.data : "");
    sb_free(&in);
    if (!parsed || parsed->type != J_OBJ) {
        j_free(parsed);
        snprintf(err, err_n, "invalid daemon JSON response");
        return DAEMON_RPC_ERR;
    }
    *resp_out = parsed;
    return DAEMON_RPC_OK;
}
