#define _POSIX_C_SOURCE 200809L

#include "store.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *xstrdup(const char *s) {
    char *p = strdup(s ? s : "");
    if (!p) abort();
    return p;
}

void login_list_free(login_list_t *l) {
    for (size_t i = 0; i < l->len; i++) {
        free(l->items[i].name);
        free(l->items[i].access);
        free(l->items[i].refresh);
        free(l->items[i].verifier);
    }
    free(l->items);
    memset(l, 0, sizeof(*l));
}

static void login_list_push(login_list_t *l, const login_t *item) {
    if (l->len == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 8;
        l->items = realloc(l->items, ncap * sizeof(login_t));
        if (!l->items) abort();
        l->cap = ncap;
    }
    l->items[l->len].name = xstrdup(item->name);
    l->items[l->len].access = xstrdup(item->access);
    l->items[l->len].refresh = xstrdup(item->refresh);
    l->items[l->len].expires = item->expires;
    l->items[l->len].verifier = xstrdup(item->verifier);
    l->len++;
}

void hold_list_free(hold_list_t *h) {
    for (size_t i = 0; i < h->len; i++) {
        free(h->items[i].id);
        free(h->items[i].model);
    }
    free(h->items);
    memset(h, 0, sizeof(*h));
}

static void hold_list_push(hold_list_t *h, const char *id, const char *model, int64_t until, bool reset) {
    if (h->len == h->cap) {
        size_t ncap = h->cap ? h->cap * 2 : 8;
        h->items = realloc(h->items, ncap * sizeof(hold_t));
        if (!h->items) abort();
        h->cap = ncap;
    }
    h->items[h->len].id = xstrdup(id);
    h->items[h->len].model = xstrdup(model);
    h->items[h->len].until = until;
    h->items[h->len].reset = reset;
    h->len++;
}

void unavail_list_free(unavail_list_t *u) {
    for (size_t i = 0; i < u->len; i++) {
        free(u->items[i].id);
        free(u->items[i].model);
    }
    free(u->items);
    memset(u, 0, sizeof(*u));
}

static void unavail_list_push(unavail_list_t *u, const char *id, const char *model) {
    if (u->len == u->cap) {
        size_t ncap = u->cap ? u->cap * 2 : 8;
        u->items = realloc(u->items, ncap * sizeof(unavail_t));
        if (!u->items) abort();
        u->cap = ncap;
    }
    u->items[u->len].id = xstrdup(id);
    u->items[u->len].model = xstrdup(model);
    u->len++;
}

void cred_list_free(cred_list_t *c) {
    for (size_t i = 0; i < c->len; i++) {
        free(c->items[i].name);
        free(c->items[i].provider);
        free(c->items[i].id);
        free(c->items[i].kind);
    }
    free(c->items);
    memset(c, 0, sizeof(*c));
}

static void cred_list_push(cred_list_t *c, const char *name, const char *provider, const char *id, const char *kind) {
    if (c->len == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 8;
        c->items = realloc(c->items, ncap * sizeof(cred_t));
        if (!c->items) abort();
        c->cap = ncap;
    }
    c->items[c->len].name = xstrdup(name);
    c->items[c->len].provider = xstrdup(provider);
    c->items[c->len].id = xstrdup(id);
    c->items[c->len].kind = xstrdup(kind);
    c->len++;
}

void str_list_free(str_list_t *s) {
    for (size_t i = 0; i < s->len; i++) free(s->items[i]);
    free(s->items);
    memset(s, 0, sizeof(*s));
}

void str_list_push(str_list_t *s, const char *v) {
    if (s->len == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 8;
        s->items = realloc(s->items, ncap * sizeof(char *));
        if (!s->items) abort();
        s->cap = ncap;
    }
    s->items[s->len++] = xstrdup(v);
}

bool str_list_has(const str_list_t *s, const char *v) {
    for (size_t i = 0; i < s->len; i++) {
        if (strcmp(s->items[i], v) == 0) return true;
    }
    return false;
}

bool auth_valid_name(const char *name, char *err, size_t err_n) {
    if (!name || !*name) {
        snprintf(err, err_n, "a login name is not empty and has no space, tab or newline");
        return false;
    }
    for (const char *p = name; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n') {
            snprintf(err, err_n, "a login name is not empty and has no space, tab or newline");
            return false;
        }
    }
    return true;
}

bool ak_valid(const char *id) {
    if (!id || !*id) return false;
    for (const unsigned char *p = (const unsigned char *)id; *p; p++) {
        if (*p == ':' || isspace(*p)) return false;
    }
    return true;
}

void ak_mask(const char *key, char *out, size_t out_n) {
    size_t n = strlen(key);
    if (n <= 4) snprintf(out, out_n, "****");
    else snprintf(out, out_n, "****%s", key + n - 4);
}

void auth_credential_id(const char *provider, const char *name, char *out, size_t out_n) {
    if (strcmp(provider, name) == 0) snprintf(out, out_n, "%s", provider);
    else snprintf(out, out_n, "%s:%s", provider, name);
}

void auth_id_for_login(const char *name, char *out, size_t out_n) {
    snprintf(out, out_n, "anthropic:%s", name);
}

static bool state_read_text(const char *rel, char **out, char *err, size_t err_n) {
    char path[1024];
    state_path(rel, path, sizeof(path));
    bool nf = false;
    if (!file_read(path, out, NULL, &nf)) {
        if (nf) {
            *out = xstrdup("");
            return true;
        }
        snprintf(err, err_n, "%s: %s", rel, strerror(errno));
        return false;
    }
    return true;
}

static bool state_write_text(const char *rel, const char *data, size_t len, char *err, size_t err_n) {
    char path[1024];
    state_path(rel, path, sizeof(path));
    if (!file_write_0600(path, data, len)) {
        snprintf(err, err_n, "%s: %s", rel, strerror(errno));
        return false;
    }
    return true;
}

bool auth_load(login_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    char *text = NULL;
    if (!state_read_text("/logins", &text, err, err_n)) return false;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (*p) {
            char *fields[8];
            int fc = 0;
            char *q = p;
            for (;;) {
                if (fc < 8) fields[fc++] = q;
                char *tab = strchr(q, '\t');
                if (!tab) break;
                *tab = '\0';
                q = tab + 1;
            }
            if (fc != 6) {
                free(text);
                login_list_free(out);
                snprintf(err, err_n, "/logins: a row does not have 6 tab-separated fields");
                return false;
            }
            int64_t exp = 0;
            if (!str_to_i64(fields[3], &exp)) {
                free(text);
                login_list_free(out);
                snprintf(err, err_n, "/logins: a row has no number in its expires field");
                return false;
            }
            login_t row = {fields[0], fields[1], fields[2], exp, fields[5]};
            login_list_push(out, &row);
        }
        if (!nl) break;
        p = nl + 1;
    }
    free(text);
    return true;
}

bool auth_save(const login_list_t *list, char *err, size_t err_n) {
    sb_t sb;
    sb_init(&sb);
    for (size_t i = 0; i < list->len; i++) {
        if (i > 0) sb_putc(&sb, '\n');
        sb_printf(&sb, "%s\t%s\t%s\t%lld\t0\t%s",
                  list->items[i].name,
                  list->items[i].access,
                  list->items[i].refresh,
                  (long long)list->items[i].expires,
                  list->items[i].verifier);
    }
    sb_putc(&sb, '\n');
    bool ok = state_write_text("/logins", sb.data, sb.len, err, err_n);
    sb_free(&sb);
    return ok;
}

bool auth_store_login(const login_t *l, char *err, size_t err_n) {
    char lock_path[1024];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    login_list_t cur = {0};
    bool ok = auth_load(&cur, err, err_n);
    if (ok) {
        login_list_t next = {0};
        for (size_t i = 0; i < cur.len; i++) {
            if (strcmp(cur.items[i].name, l->name) != 0) login_list_push(&next, &cur.items[i]);
        }
        login_list_push(&next, l);
        ok = auth_save(&next, err, err_n);
        login_list_free(&next);
    }
    login_list_free(&cur);
    file_unlock(fd);
    return ok;
}

bool auth_remove_login(const char *name, char *err, size_t err_n) {
    char lock_path[1024];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    login_list_t cur = {0};
    bool ok = auth_load(&cur, err, err_n);
    if (ok) {
        login_list_t next = {0};
        for (size_t i = 0; i < cur.len; i++) {
            if (strcmp(cur.items[i].name, name) != 0) login_list_push(&next, &cur.items[i]);
        }
        ok = auth_save(&next, err, err_n);
        login_list_free(&next);
    }
    login_list_free(&cur);
    file_unlock(fd);
    return ok;
}

bool auth_is_login(const char *name, bool *out, char *err, size_t err_n) {
    login_list_t cur = {0};
    if (!auth_load(&cur, err, err_n)) return false;
    *out = false;
    for (size_t i = 0; i < cur.len; i++) {
        if (strcmp(cur.items[i].name, name) == 0) {
            *out = true;
            break;
        }
    }
    login_list_free(&cur);
    return true;
}

bool auth_names(str_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    char *text = NULL;
    if (!state_read_text("/order", &text, err, err_n)) return false;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *t = str_trim(p);
        if (*t) str_list_push(out, t);
        if (!nl) break;
        p = nl + 1;
    }
    free(text);
    return true;
}

static bool auth_write_names_unlocked(const str_list_t *names, char *err, size_t err_n) {
    for (size_t i = 0; i < names->len; i++) {
        const char *n = names->items[i];
        if (!n || !n[0] || strchr(n, '\n') || strchr(n, '\r')) {
            snprintf(err, err_n, "invalid credential name in order");
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(names->items[j], n) == 0) {
                snprintf(err, err_n, "duplicate credential name in order: %s", n);
                return false;
            }
        }
    }
    sb_t sb;
    sb_init(&sb);
    for (size_t i = 0; i < names->len; i++) {
        if (i > 0) sb_putc(&sb, '\n');
        sb_puts(&sb, names->items[i]);
    }
    sb_putc(&sb, '\n');
    bool ok = state_write_text("/order", sb.data, sb.len, err, err_n);
    sb_free(&sb);
    return ok;
}

bool auth_write_names(const str_list_t *names, char *err, size_t err_n) {
    char lock_path[1024];
    state_path("/order.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    bool ok = auth_write_names_unlocked(names, err, err_n);
    file_unlock(fd);
    return ok;
}

bool auth_order_update(auth_order_fn fn, void *ctx, char *err, size_t err_n) {
    char lock_path[1024];
    state_path("/order.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    str_list_t cur = {0};
    str_list_t next = {0};
    bool ok = auth_names(&cur, err, err_n);
    if (ok) ok = fn(&cur, &next, ctx, err, err_n);
    if (ok) ok = auth_write_names_unlocked(&next, err, err_n);
    str_list_free(&next);
    str_list_free(&cur);
    file_unlock(fd);
    return ok;
}

bool ak_read(jval_t **out, char *err, size_t err_n) {
    *out = NULL;
    char *text = NULL;
    if (!state_read_text("/auth.json", &text, err, err_n)) return false;
    char *t = str_trim(text);
    if (!*t) {
        free(text);
        *out = j_obj();
        return true;
    }
    jval_t *j = j_parse(t);
    free(text);
    if (!j || j->type != J_OBJ) {
        j_free(j);
        snprintf(err, err_n, "/auth.json must be a JSON object");
        return false;
    }
    *out = j;
    return true;
}

bool ak_write(const jval_t *obj, char *err, size_t err_n) {
    sb_t sb;
    sb_init(&sb);
    j_emit(obj, &sb);
    sb_putc(&sb, '\n');
    bool ok = state_write_text("/auth.json", sb.data, sb.len, err, err_n);
    sb_free(&sb);
    return ok;
}

const char *ak_provider(const char *name, const jval_t *entry) {
    const char *p = j_str_at(entry, "provider");
    return (*p) ? p : name;
}

bool ak_get(const char *name, jval_t **out, char *err, size_t err_n) {
    *out = NULL;
    jval_t *root = NULL;
    if (!ak_read(&root, err, err_n)) return false;
    jval_t *v = j_obj_get(root, name);
    if (v) *out = j_clone(v);
    j_free(root);
    return true;
}

bool ak_put(const char *name, jval_t *entry, char *err, size_t err_n) {
    if (!ak_valid(name)) {
        j_free(entry);
        snprintf(err, err_n, "invalid credential name");
        return false;
    }
    char lock_path[1088];
    state_path("/auth.json.lock", lock_path, sizeof(lock_path));
    int lfd = -1;
    if (!file_lock(lock_path, &lfd, err, err_n)) {
        j_free(entry);
        return false;
    }
    jval_t *root = NULL;
    if (!ak_read(&root, err, err_n)) {
        file_unlock(lfd);
        j_free(entry);
        return false;
    }
    j_obj_set(root, name, entry);
    bool ok = ak_write(root, err, err_n);
    j_free(root);
    file_unlock(lfd);
    return ok;
}

bool ak_remove(const char *name, char *err, size_t err_n) {
    char lock_path[1088];
    state_path("/auth.json.lock", lock_path, sizeof(lock_path));
    int lfd = -1;
    if (!file_lock(lock_path, &lfd, err, err_n)) return false;
    jval_t *root = NULL;
    if (!ak_read(&root, err, err_n)) {
        file_unlock(lfd);
        return false;
    }
    if (!j_obj_del(root, name)) {
        j_free(root);
        file_unlock(lfd);
        snprintf(err, err_n, "no stored credential for %s", name);
        return false;
    }
    bool ok = ak_write(root, err, err_n);
    j_free(root);
    file_unlock(lfd);
    return ok;
}

bool ak_set_named(const char *provider, const char *name, const char *key, char *err, size_t err_n) {
    if (!ak_valid(provider)) {
        snprintf(err, err_n, "invalid provider name");
        return false;
    }
    char *kcopy = xstrdup(key);
    char *kt = str_trim(kcopy);
    if (!*kt) {
        free(kcopy);
        snprintf(err, err_n, "a key is empty");
        return false;
    }
    jval_t *e = j_obj();
    j_obj_set(e, "provider", j_str(provider));
    j_obj_set(e, "type", j_str("api_key"));
    j_obj_set(e, "key", j_str(kt));
    free(kcopy);
    return ak_put(name, e, err, err_n);
}

static bool parse_whole(const char *v, int64_t *out) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", v ? v : "");
    char *t = str_trim(buf);
    char *dot = strchr(t, '.');
    if (dot) *dot = '\0';
    return str_to_i64(t, out);
}

static bool ends_with(const char *s, const char *suf) {
    size_t sl = strlen(s), fl = strlen(suf);
    return sl >= fl && strcmp(s + sl - fl, suf) == 0;
}

static bool auth_when(const char *name, const char *v, int64_t now, int64_t *out) {
    int64_t n = 0;
    if (parse_whole(v, &n)) {
        if (n >= 100000000000LL) *out = n;
        else if (n >= 1000000000LL) *out = n * 1000;
        else *out = now + n * (ends_with(name, "-ms") ? 1 : 1000);
        return true;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", v ? v : "");
    return parse_iso8601_ms(str_trim(buf), out);
}

static const char *hdr_get(const kv_t *headers, size_t hcnt, const char *name) {
    for (size_t i = 0; i < hcnt; i++) {
        if (strcmp(headers[i].k, name) == 0) return headers[i].v;
    }
    return NULL;
}

static bool auth_spent(const kv_t *headers, size_t hcnt, const char *stem, const char *tail) {
    char key[256];
    int64_t n = 0;
    snprintf(key, sizeof(key), "%sremaining%s", stem, tail);
    const char *v = hdr_get(headers, hcnt, key);
    if (v && parse_whole(v, &n) && n <= 0) return true;
    snprintf(key, sizeof(key), "%sused-percent", stem);
    v = hdr_get(headers, hcnt, key);
    if (v && parse_whole(v, &n) && n >= 100) return true;
    snprintf(key, sizeof(key), "%sutilization", stem);
    v = hdr_get(headers, hcnt, key);
    if (v && parse_whole(v, &n) && n >= 1) return true;
    snprintf(key, sizeof(key), "%sstatus", stem);
    v = hdr_get(headers, hcnt, key);
    if (v && strcmp(v, "rejected") == 0) return true;
    return false;
}

static bool auth_reset(const kv_t *headers, size_t hcnt, int64_t now, int64_t *out) {
    const char *v = hdr_get(headers, hcnt, "retry-after-ms");
    int64_t t = 0;
    if (v && auth_when("retry-after-ms", v, now, &t) && t > now) {
        *out = t;
        return true;
    }
    v = hdr_get(headers, hcnt, "retry-after");
    if (v && auth_when("retry-after", v, now, &t) && t > now) {
        *out = t;
        return true;
    }
    int64_t best = 0;
    for (size_t i = 0; i < hcnt; i++) {
        const char *r = strstr(headers[i].k, "reset");
        if (!r || strstr(r + 5, "reset")) continue;
        char stem[128];
        size_t sl = (size_t)(r - headers[i].k);
        if (sl >= sizeof(stem)) continue;
        memcpy(stem, headers[i].k, sl);
        stem[sl] = '\0';
        const char *tail = r + 5;
        if (auth_spent(headers, hcnt, stem, tail)) {
            if (auth_when(headers[i].k, headers[i].v, now, &t) && t > best) best = t;
        }
    }
    if (best > now) {
        *out = best;
        return true;
    }
    return false;
}

bool auth_holds(hold_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    char *text = NULL;
    if (!state_read_text("/limits", &text, err, err_n)) return false;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (*p) {
            char *fields[6];
            int fc = 0;
            char *q = p;
            for (;;) {
                if (fc < 6) fields[fc++] = q;
                char *tab = strchr(q, '\t');
                if (!tab) break;
                *tab = '\0';
                q = tab + 1;
            }
            int64_t u = 0;
            if (fc == 4 && str_to_i64(fields[2], &u)) {
                hold_list_push(out, fields[0], fields[1], u, strcmp(fields[3], "reset") == 0);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    free(text);
    return true;
}

static bool write_holds(const hold_list_t *holds, char *err, size_t err_n) {
    sb_t sb;
    sb_init(&sb);
    for (size_t i = 0; i < holds->len; i++) {
        sb_printf(&sb, "%s\t%s\t%lld\t%s\n",
                  holds->items[i].id,
                  holds->items[i].model,
                  (long long)holds->items[i].until,
                  holds->items[i].reset ? "reset" : "cool");
    }
    bool ok = state_write_text("/limits", sb.data, sb.len, err, err_n);
    sb_free(&sb);
    return ok;
}

bool auth_limit(const char *id, const char *model, int status, const kv_t *headers, size_t hcnt, int64_t cooldown_ms, bool *limited_out, char *err, size_t err_n) {
    *limited_out = false;
    if (!id || !id[0] || strchr(id, '\t') || strchr(id, '\r') || strchr(id, '\n')) {
        snprintf(err, err_n, "invalid credential id");
        return false;
    }
    if (model && (strchr(model, '\t') || strchr(model, '\r') || strchr(model, '\n'))) {
        snprintf(err, err_n, "a model id has no tab or newline");
        return false;
    }
    if (cooldown_ms < 0 || cooldown_ms > AUTH_MAX_COOLDOWN_MS) {
        snprintf(err, err_n, "cooldown_ms out of range");
        return false;
    }
    if (status != 429 && status != 402) return true;
    int64_t now = now_ms();
    int64_t until = now + cooldown_ms;
    bool has_reset = auth_reset(headers, hcnt, now, &until);
    char lock_path[1024];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    hold_list_t cur = {0};
    bool ok = auth_holds(&cur, err, err_n);
    if (ok) {
        hold_list_t active = {0};
        bool keep_existing = false;
        for (size_t i = 0; i < cur.len; i++) {
            if (cur.items[i].until > now) {
                hold_list_push(&active, cur.items[i].id, cur.items[i].model, cur.items[i].until, cur.items[i].reset);
                if (!has_reset && strcmp(cur.items[i].id, id) == 0 && strcmp(cur.items[i].model, model) == 0 && cur.items[i].until > until) {
                    keep_existing = true;
                }
            }
        }
        if (keep_existing) {
            ok = write_holds(&active, err, err_n);
        } else {
            hold_list_t next = {0};
            hold_list_push(&next, id, model, until, has_reset);
            for (size_t i = 0; i < active.len; i++) {
                if (!(strcmp(active.items[i].id, id) == 0 && strcmp(active.items[i].model, model) == 0)) {
                    hold_list_push(&next, active.items[i].id, active.items[i].model, active.items[i].until, active.items[i].reset);
                }
            }
            ok = write_holds(&next, err, err_n);
            hold_list_free(&next);
        }
        hold_list_free(&active);
    }
    hold_list_free(&cur);
    file_unlock(fd);
    if (ok) *limited_out = true;
    return ok;
}

bool auth_models(unavail_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    char *text = NULL;
    if (!state_read_text("/unavailable", &text, err, err_n)) return false;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (*p) {
            char *tab = strchr(p, '\t');
            if (tab && !strchr(tab + 1, '\t')) {
                *tab = '\0';
                unavail_list_push(out, p, tab + 1);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    free(text);
    return true;
}

bool auth_unavailable(const char *id, const char *model, const unavail_list_t *rows) {
    for (size_t i = 0; i < rows->len; i++) {
        if (strcmp(rows->items[i].id, id) == 0 && strcmp(rows->items[i].model, model) == 0) return true;
    }
    return false;
}

bool auth_model_update(const char *id, const char *model, bool missing, char *err, size_t err_n) {
    if (!id || !id[0] || strchr(id, '\t') || strchr(id, '\r') || strchr(id, '\n')) {
        snprintf(err, err_n, "invalid credential id");
        return false;
    }
    if (missing && (!model || !model[0] || strchr(model, '\t') || strchr(model, '\r') || strchr(model, '\n'))) {
        snprintf(err, err_n, "invalid model id");
        return false;
    }
    char lock_path[1024];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    unavail_list_t cur = {0};
    bool ok = auth_models(&cur, err, err_n);
    if (ok) {
        sb_t sb;
        sb_init(&sb);
        if (missing) {
            if (!auth_unavailable(id, model, &cur)) sb_printf(&sb, "%s\t%s\n", id, model);
            for (size_t i = 0; i < cur.len; i++) sb_printf(&sb, "%s\t%s\n", cur.items[i].id, cur.items[i].model);
        } else {
            for (size_t i = 0; i < cur.len; i++) {
                if (strcmp(cur.items[i].id, id) != 0) sb_printf(&sb, "%s\t%s\n", cur.items[i].id, cur.items[i].model);
            }
        }
        ok = state_write_text("/unavailable", sb.data, sb.len, err, err_n);
        sb_free(&sb);
    }
    unavail_list_free(&cur);
    file_unlock(fd);
    return ok;
}

bool auth_model_missing(const char *id, const char *model, int status, const char *body, bool *missing_out, char *err, size_t err_n) {
    *missing_out = false;
    if (status != 404 || !model || !*model) return true;
    jval_t *root = j_parse(body ? body : "");
    jval_t *eobj = root ? j_obj_get(root, "error") : NULL;
    if (!eobj) eobj = root;
    const char *code = j_str_at(eobj, "code");
    const char *msg = j_str_at(eobj, "message");
    bool missing = (strcmp(code, "model_not_found") == 0);
    if (!missing && str_contains_ci(msg, model)) {
        if (str_contains_ci(msg, "model:") ||
            str_contains_ci(msg, "unknown model") ||
            str_contains_ci(msg, "model not found") ||
            str_contains_ci(msg, "does not exist") ||
            str_contains_ci(msg, "not available")) {
            missing = true;
        }
    }
    j_free(root);
    if (missing) {
        if (!auth_model_update(id, model, true, err, err_n)) return false;
        *missing_out = true;
    }
    return true;
}

bool auth_forget(const char *id, char *err, size_t err_n) {
    char lock_path[1024];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;
    hold_list_t cur = {0};
    bool ok = auth_holds(&cur, err, err_n);
    if (ok) {
        int64_t now = now_ms();
        hold_list_t next = {0};
        for (size_t i = 0; i < cur.len; i++) {
            if (cur.items[i].until > now && strcmp(cur.items[i].id, id) != 0) {
                hold_list_push(&next, cur.items[i].id, cur.items[i].model, cur.items[i].until, cur.items[i].reset);
            }
        }
        ok = write_holds(&next, err, err_n);
        hold_list_free(&next);
    }
    hold_list_free(&cur);
    file_unlock(fd);
    if (!ok) return false;
    return auth_model_update(id, "", false, err, err_n);
}

int64_t auth_reading(const char *id, const char *model) {
    char hex[65];
    sha256_hex(id, hex);
    hex[32] = '\0';
    char rel[128];
    snprintf(rel, sizeof(rel), "/probes/%s.ok.json", hex);
    char path[1024];
    state_path(rel, path, sizeof(path));
    char *text = NULL;
    if (!file_read(path, &text, NULL, NULL)) return 0;
    jval_t *j = j_parse(text);
    free(text);
    if (!j) return 0;
    jval_t *wins = j_obj_get(j, "windows");
    int64_t best = 0;
    if (wins && wins->type == J_ARR) {
        for (size_t i = 0; i < wins->arr_len; i++) {
            jval_t *w = wins->arr[i];
            const char *scope = j_str_at(w, "scope");
            bool match = (!*scope) || (model && *model && str_contains_ci(model, scope));
            int64_t used = 0, reset = 0;
            j_int_at(w, "used", &used);
            j_int_at(w, "reset", &reset);
            if (match && used >= 100 && reset > best) best = reset;
        }
    }
    j_free(j);
    return best;
}

hold_t auth_hold_for(const char *id, const char *model, const hold_list_t *holds) {
    hold_t acc;
    acc.id = (char *)id;
    acc.model = "";
    acc.until = auth_reading(id, model);
    acc.reset = true;
    for (size_t i = 0; i < holds->len; i++) {
        if (strcmp(holds->items[i].id, id) == 0 &&
            (holds->items[i].model[0] == '\0' || strcmp(holds->items[i].model, model) == 0)) {
            if (holds->items[i].until > acc.until) {
                acc = holds->items[i];
            }
        }
    }
    return acc;
}

void auth_span(int64_t ms, char *out, size_t n) {
    int64_t mins = (ms + 59999) / 60000;
    if (mins >= 120) snprintf(out, n, "%lldh%lldm", (long long)(mins / 60), (long long)(mins % 60));
    else snprintf(out, n, "%lldm", (long long)mins);
}

void auth_rest(const hold_t *h, int64_t now, char *out, size_t n) {
    if (h->until <= now) {
        snprintf(out, n, "ready");
        return;
    }
    char span[64];
    auth_span(h->until - now, span, sizeof(span));
    snprintf(out, n, "%s%s", h->reset ? "limited, resets in " : "cooling ", span);
}

void auth_health(const char *id, const hold_list_t *holds, int64_t now, char *out, size_t n) {
    sb_t sb;
    sb_init(&sb);
    int cnt = 0;
    hold_t base = auth_hold_for(id, "", holds);
    if (base.until > now) {
        char r[128];
        auth_rest(&base, now, r, sizeof(r));
        sb_puts(&sb, r);
        cnt++;
    }
    for (size_t i = 0; i < holds->len; i++) {
        if (strcmp(holds->items[i].id, id) == 0 && holds->items[i].model[0] != '\0' && holds->items[i].until > now) {
            if (cnt > 0) sb_puts(&sb, "; ");
            char r[128];
            auth_rest(&holds->items[i], now, r, sizeof(r));
            sb_printf(&sb, "%s %s", holds->items[i].model, r);
            cnt++;
        }
    }
    if (cnt == 0) snprintf(out, n, "ready");
    else snprintf(out, n, "%s", sb.data);
    sb_free(&sb);
}

void auth_expiry(const login_t *l, int64_t now, char *out, size_t n) {
    if (!l->access[0]) {
        snprintf(out, n, "-");
    } else if (l->expires <= now) {
        snprintf(out, n, "expired");
    } else {
        char span[64];
        auth_span(l->expires - now, span, sizeof(span));
        snprintf(out, n, "expires in %s", span);
    }
}

void auth_line(const login_t *l, const hold_list_t *holds, int64_t now, sb_t *out) {
    char id[256], health[256], exp[128];
    auth_id_for_login(l->name, id, sizeof(id));
    if (!l->access[0]) snprintf(health, sizeof(health), "pending");
    else auth_health(id, holds, now, health, sizeof(health));
    auth_expiry(l, now, exp, sizeof(exp));
    sb_printf(out, "%s\t%s\t%s", l->name, health, exp);
}

bool auth_rank(const str_list_t *names, const login_list_t *logins, login_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    jval_t *ak = NULL;
    if (!ak_read(&ak, err, err_n)) return false;
    login_list_t fin = {0};
    for (size_t i = 0; i < logins->len; i++) {
        if (logins->items[i].access[0]) login_list_push(&fin, &logins->items[i]);
    }
    bool *used = calloc(fin.len ? fin.len : 1, sizeof(bool));
    for (size_t i = 0; i < names->len; i++) {
        if (j_obj_get(ak, names->items[i])) continue;
        for (size_t j = 0; j < fin.len; j++) {
            if (!used[j] && strcmp(fin.items[j].name, names->items[i]) == 0) {
                used[j] = true;
                login_list_push(out, &fin.items[j]);
                break;
            }
        }
    }
    for (size_t j = 0; j < fin.len; j++) {
        if (!used[j]) login_list_push(out, &fin.items[j]);
    }
    free(used);
    login_list_free(&fin);
    j_free(ak);
    return true;
}

bool auth_credential_pick(const str_list_t *names, const cred_list_t *pool, cred_list_t *out, char *err, size_t err_n) {
    (void)err;
    (void)err_n;
    memset(out, 0, sizeof(*out));
    bool *used = calloc(pool->len ? pool->len : 1, sizeof(bool));
    for (size_t i = 0; i < names->len; i++) {
        for (size_t j = 0; j < pool->len; j++) {
            if (!used[j] && strcmp(pool->items[j].name, names->items[i]) == 0) {
                used[j] = true;
                cred_list_push(out, pool->items[j].name, pool->items[j].provider, pool->items[j].id, pool->items[j].kind);
                break;
            }
        }
    }
    for (size_t j = 0; j < pool->len; j++) {
        if (!used[j]) {
            cred_list_push(out, pool->items[j].name, pool->items[j].provider, pool->items[j].id, pool->items[j].kind);
        }
    }
    free(used);
    return true;
}

bool auth_credentials(cred_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    login_list_t logins = {0};
    if (!auth_load(&logins, err, err_n)) return false;
    jval_t *ak = NULL;
    if (!ak_read(&ak, err, err_n)) {
        login_list_free(&logins);
        return false;
    }
    str_list_t names = {0};
    if (!auth_names(&names, err, err_n)) {
        login_list_free(&logins);
        j_free(ak);
        return false;
    }
    cred_list_t pool = {0};
    for (size_t i = 0; i < logins.len; i++) {
        char id[256];
        auth_id_for_login(logins.items[i].name, id, sizeof(id));
        cred_list_push(&pool, logins.items[i].name, "anthropic", id, "login");
    }
    for (size_t i = 0; i < ak->obj_len; i++) {
        const char *name = ak->obj[i].key;
        const jval_t *entry = ak->obj[i].val;
        const char *kind = j_str_at(entry, "type");
        if (strcmp(kind, "api_key") == 0 || strcmp(kind, "oauth") == 0 || strcmp(kind, "acp") == 0) {
            const char *prov = ak_provider(name, entry);
            char id[256];
            auth_credential_id(prov, name, id, sizeof(id));
            cred_list_push(&pool, name, prov, id, kind);
        }
    }
    bool ok = auth_credential_pick(&names, &pool, out, err, err_n);
    cred_list_free(&pool);
    str_list_free(&names);
    j_free(ak);
    login_list_free(&logins);
    return ok;
}

bool auth_routable_credentials(cred_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    login_list_t logins = {0};
    if (!auth_load(&logins, err, err_n)) return false;
    cred_list_t all = {0};
    if (!auth_credentials(&all, err, err_n)) {
        login_list_free(&logins);
        return false;
    }
    for (size_t i = 0; i < all.len; i++) {
        if (strcmp(all.items[i].kind, "acp") == 0) continue;
        if (strcmp(all.items[i].kind, "login") == 0) {
            bool fin = false;
            for (size_t j = 0; j < logins.len; j++) {
                if (strcmp(logins.items[j].name, all.items[i].name) == 0 && logins.items[j].access[0]) {
                    fin = true;
                    break;
                }
            }
            if (!fin) continue;
        }
        cred_list_push(out, all.items[i].name, all.items[i].provider, all.items[i].id, all.items[i].kind);
    }
    cred_list_free(&all);
    login_list_free(&logins);
    return true;
}

bool auth_provider_pool(const char *provider, cred_list_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    login_list_t logins = {0};
    if (!auth_load(&logins, err, err_n)) return false;
    cred_list_t all = {0};
    if (!auth_credentials(&all, err, err_n)) {
        login_list_free(&logins);
        return false;
    }
    for (size_t i = 0; i < all.len; i++) {
        if (strcmp(all.items[i].provider, provider) != 0) continue;
        if (strcmp(all.items[i].kind, "acp") == 0) continue;
        if (strcmp(all.items[i].kind, "login") == 0) {
            bool fin = false;
            for (size_t j = 0; j < logins.len; j++) {
                if (strcmp(logins.items[j].name, all.items[i].name) == 0 && logins.items[j].access[0]) {
                    fin = true;
                    break;
                }
            }
            if (!fin) continue;
        }
        cred_list_push(out, all.items[i].name, all.items[i].provider, all.items[i].id, all.items[i].kind);
    }
    cred_list_free(&all);
    login_list_free(&logins);
    return true;
}

bool acp_name_ok(const char *name) {
    if (!name || !*name || name[0] == '.') return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p == ':' || *p == '/' || isspace(*p)) return false;
    }
    return true;
}

void acp_dir(const char *name, char *out, size_t n) {
    char dir[1024];
    state_dir(dir, sizeof(dir));
    snprintf(out, n, "%s/antigravity/%s", dir, name);
}

bool acp_is(const char *name, const jval_t *entry) {
    return strcmp(j_str_at(entry, "type"), "acp") == 0 &&
           strcmp(ak_provider(name, entry), ACP_PROVIDER) == 0;
}

bool acp_email(const char *name, char *out, size_t n) {
    out[0] = '\0';
    char rel[256];
    snprintf(rel, sizeof(rel), "/antigravity/%s/crest-login.json", name);
    char path[1024];
    state_path(rel, path, sizeof(path));
    char *text = NULL;
    if (!file_read(path, &text, NULL, NULL)) return false;
    jval_t *j = j_parse(text);
    free(text);
    if (!j) return false;
    const char *e = j_str_at(j, "email");
    snprintf(out, n, "%s", e);
    j_free(j);
    return out[0] != '\0';
}

bool acp_signed(const char *name) {
    char email[256];
    return acp_email(name, email, sizeof(email));
}

void acp_note(const char *name, char *out, size_t n) {
    char email[256];
    if (acp_email(name, email, sizeof(email))) snprintf(out, n, "signed in as %s", email);
    else snprintf(out, n, "not signed in");
}

bool acp_active(char *out, size_t n, bool *has_active, char *err, size_t err_n) {
    *has_active = false;
    out[0] = '\0';
    jval_t *ak = NULL;
    if (!ak_read(&ak, err, err_n)) return false;
    str_list_t names = {0};
    for (size_t i = 0; i < ak->obj_len; i++) {
        if (acp_is(ak->obj[i].key, ak->obj[i].val)) str_list_push(&names, ak->obj[i].key);
    }
    j_free(ak);
    str_list_t order = {0};
    if (!auth_names(&order, err, err_n)) {
        str_list_free(&names);
        return false;
    }
    for (size_t i = 0; i < order.len; i++) {
        if (str_list_has(&names, order.items[i])) {
            snprintf(out, n, "%s", order.items[i]);
            *has_active = true;
            break;
        }
    }
    if (!*has_active && names.len > 0) {
        snprintf(out, n, "%s", names.items[0]);
        *has_active = true;
    }
    str_list_free(&order);
    str_list_free(&names);
    return true;
}

bool acp_free(const char *name, char *err, size_t err_n) {
    if (!acp_name_ok(name)) {
        snprintf(err, err_n, "an Antigravity account name may not be empty, start with '.', or hold ':', '/' or spaces");
        return false;
    }
    jval_t *entry = NULL;
    if (!ak_get(name, &entry, err, err_n)) return false;
    if (entry) {
        if (!acp_is(name, entry)) {
            snprintf(err, err_n, "%s belongs to %s", name, ak_provider(name, entry));
            j_free(entry);
            return false;
        }
        j_free(entry);
    }
    return true;
}

bool acp_add(const char *name, char *err, size_t err_n) {
    if (!acp_free(name, err, err_n)) return false;
    char dir[1024];
    acp_dir(name, dir, sizeof(dir));
    if (!ensure_dir(dir, 0700)) {
        snprintf(err, err_n, "%s: %s", dir, strerror(errno));
        return false;
    }
    char marker[1100];
    snprintf(marker, sizeof(marker), "%s/crest-login.json", dir);
    char *existing = NULL;
    bool nf = false;
    if (!file_read(marker, &existing, NULL, &nf)) {
        const char *init = "{\"version\":2}\n";
        if (!file_write_0600(marker, init, strlen(init))) {
            snprintf(err, err_n, "%s: %s", marker, strerror(errno));
            return false;
        }
    } else {
        free(existing);
    }
    jval_t *e = j_obj();
    j_obj_set(e, "provider", j_str(ACP_PROVIDER));
    j_obj_set(e, "type", j_str("acp"));
    return ak_put(name, e, err, err_n);
}

bool acp_activate(const char *name, char *err, size_t err_n) {
    str_list_t order = {0};
    if (!auth_names(&order, err, err_n)) return false;
    str_list_t next = {0};
    str_list_push(&next, name);
    for (size_t i = 0; i < order.len; i++) {
        if (strcmp(order.items[i], name) != 0) str_list_push(&next, order.items[i]);
    }
    bool ok = auth_write_names(&next, err, err_n);
    str_list_free(&order);
    str_list_free(&next);
    return ok;
}

static bool acp_email_ok(const char *email) {
    if (!strchr(email, '@')) return false;
    for (const unsigned char *p = (const unsigned char *)email; *p; p++) {
        if (*p == '"' || *p == '\\' || isspace(*p)) return false;
    }
    return true;
}

bool acp_confirm(const char *name, const char *email, char *err, size_t err_n) {
    if (!acp_free(name, err, err_n)) return false;
    if (!acp_email_ok(email)) {
        snprintf(err, err_n, "'%s' is not a Google account; %s is not active", email, name);
        return false;
    }
    if (!acp_add(name, err, err_n)) return false;
    jval_t *m = j_obj();
    j_obj_set(m, "version", j_int(2));
    j_obj_set(m, "provider", j_str("antigravity-cli"));
    j_obj_set(m, "email", j_str(email));
    sb_t sb;
    sb_init(&sb);
    j_emit(m, &sb);
    sb_putc(&sb, '\n');
    j_free(m);
    char dir[1024], marker[1100];
    acp_dir(name, dir, sizeof(dir));
    snprintf(marker, sizeof(marker), "%s/crest-login.json", dir);
    bool ok = file_write_0600(marker, sb.data, sb.len);
    sb_free(&sb);
    if (!ok) {
        snprintf(err, err_n, "%s: %s", marker, strerror(errno));
        return false;
    }
    return acp_activate(name, err, err_n);
}
