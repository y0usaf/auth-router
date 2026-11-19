#define _POSIX_C_SOURCE 200809L

#include "oauth.h"
#include "http.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *AUTH_SCOPE =
    "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
static const char *AUTH_PAGE =
    "<!doctype html><meta charset=utf-8><title>Signed in</title><p>Signed in. You can close this tab.</p>";

static char *xstrdup(const char *s) {
    char *p = strdup(s ? s : "");
    if (!p) abort();
    return p;
}

void oa_tok_free(oa_tok_t *t) {
    free(t->access);
    free(t->refresh);
    j_free(t->extra);
    memset(t, 0, sizeof(*t));
}

static const char *KNOWN_IDS[] = {
    "openai-codex", "xai", "kimi-coding", "github-copilot", "openrouter", "meta",
    "qwen-oauth", "nous", "minimax", "openai", "google-gemini-cli", "google-antigravity", NULL
};

static const char *DEVICE_IDS[] = {
    "xai", "kimi-coding", "github-copilot", "meta", "qwen-oauth", "nous", "minimax", NULL
};

bool oa_known(const char *id) {
    for (int i = 0; KNOWN_IDS[i]; i++) {
        if (strcmp(KNOWN_IDS[i], id) == 0) return true;
    }
    return false;
}

const char *oa_flow_kind(const char *id) {
    for (int i = 0; DEVICE_IDS[i]; i++) {
        if (strcmp(DEVICE_IDS[i], id) == 0) return "device";
    }
    return "";
}

static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

void auth_link(const char *redirect, const char *challenge, const char *state, sb_t *out) {
    sb_puts(out, AUTH_AUTHORIZE_URL "?code=true&client_id=" AUTH_CLIENT_ID "&response_type=code&redirect_uri=");
    url_encode(redirect, out);
    sb_puts(out, "&scope=");
    url_encode(AUTH_SCOPE, out);
    sb_puts(out, "&code_challenge=");
    url_encode(challenge, out);
    sb_puts(out, "&code_challenge_method=S256&state=");
    url_encode(state, out);
}

static bool query_get(const char *query, const char *key, char *out, size_t out_n) {
    const char *p = query;
    size_t klen = strlen(key);
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', len);
        if (eq && (size_t)(eq - p) == klen && memcmp(p, key, klen) == 0) {
            size_t vlen = len - klen - 1;
            char *raw = malloc(vlen + 1);
            memcpy(raw, eq + 1, vlen);
            raw[vlen] = '\0';
            sb_t dec;
            sb_init(&dec);
            url_decode(raw, &dec);
            snprintf(out, out_n, "%s", dec.data);
            sb_free(&dec);
            free(raw);
            return true;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return false;
}

bool auth_code_parse(const char *heard, const char *verifier, char *code_out, size_t code_n, char *state_out, size_t state_n, char *err, size_t err_n) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", heard ? heard : "");
    char *s = str_trim(buf);
    if (!*s) {
        snprintf(err, err_n, "the callback had no authorization code");
        return false;
    }
    char *q = strchr(s, '?');
    if (q) s = q + 1;
    char *hash = strchr(s, '#');
    if (hash && !strchr(s, '=')) {
        *hash = '\0';
        snprintf(code_out, code_n, "%s", s);
        snprintf(state_out, state_n, "%s", hash + 1);
        return true;
    }
    if (strchr(s, '=')) {
        char ebuf[256];
        if (query_get(s, "error", ebuf, sizeof(ebuf)) && ebuf[0]) {
            snprintf(err, err_n, "the sign-in was refused: %s", ebuf);
            return false;
        }
        if (!query_get(s, "code", code_out, code_n) || !code_out[0]) {
            snprintf(err, err_n, "the callback had no authorization code");
            return false;
        }
        if (!query_get(s, "state", state_out, state_n)) {
            snprintf(state_out, state_n, "%s", verifier ? verifier : "");
        }
        return true;
    }
    snprintf(code_out, code_n, "%s", s);
    snprintf(state_out, state_n, "%s", verifier ? verifier : "");
    return true;
}

static bool auth_token_call(const char *what, const jval_t *payload, char **access_out, char **refresh_out, int64_t *expires_out, char *err, size_t err_n) {
    const char *url = env_or("CREST_AUTH_TOKEN_URL", AUTH_TOKEN_URL);
    const char *hdrs[3] = {
        "Content-Type: application/json",
        "Accept: application/json",
        "User-Agent: " AUTH_AGENT
    };
    char *body = j_show(payload);
    http_resp_t resp;
    char herr[256];
    bool ok = http_request("POST", url, body, hdrs, 3, 120000, &resp, herr, sizeof(herr));
    free(body);
    if (!ok) {
        snprintf(err, err_n, "%s: %s", what, herr);
        return false;
    }
    if (resp.status != 200) {
        snprintf(err, err_n, "%s: HTTP %d: %s", what, resp.status, resp.body ? resp.body : "");
        http_resp_free(&resp);
        return false;
    }
    jval_t *j = j_parse(resp.body ? resp.body : "");
    http_resp_free(&resp);
    if (!j) {
        snprintf(err, err_n, "%s: invalid JSON response", what);
        return false;
    }
    const char *acc = j_str_at(j, "access_token");
    const char *ref = j_str_at(j, "refresh_token");
    int64_t secs = 0;
    if (!*acc) {
        j_free(j);
        snprintf(err, err_n, "the token reply has no access_token");
        return false;
    }
    if (!*ref) {
        j_free(j);
        snprintf(err, err_n, "the token reply has no refresh_token");
        return false;
    }
    if (!j_int_at(j, "expires_in", &secs)) {
        j_free(j);
        snprintf(err, err_n, "the token reply has no whole-number expires_in");
        return false;
    }
    *access_out = xstrdup(acc);
    *refresh_out = xstrdup(ref);
    *expires_out = now_ms() + secs * 1000;
    j_free(j);
    return true;
}

static bool order_append_cb(const str_list_t *cur, str_list_t *next, void *ctx, char *err, size_t err_n) {
    const char *name = (const char *)ctx;
    (void)err;
    (void)err_n;
    for (size_t i = 0; i < cur->len; i++) {
        if (strcmp(cur->items[i], name) != 0) str_list_push(next, cur->items[i]);
    }
    str_list_push(next, name);
    return true;
}

bool auth_complete(const login_t *current, const char *code, const char *state, const char *redirect, bool quiet, char *err, size_t err_n) {
    if (strcmp(state, current->verifier) != 0) {
        snprintf(err, err_n, "OAuth state mismatch; run crest-auth login again and use the newest link");
        return false;
    }
    jval_t *p = j_obj();
    j_obj_set(p, "grant_type", j_str("authorization_code"));
    j_obj_set(p, "client_id", j_str(AUTH_CLIENT_ID));
    j_obj_set(p, "code", j_str(code));
    j_obj_set(p, "state", j_str(state));
    j_obj_set(p, "redirect_uri", j_str(redirect));
    j_obj_set(p, "code_verifier", j_str(current->verifier));
    char what[256];
    snprintf(what, sizeof(what), "login %s", current->name);
    char *acc = NULL, *ref = NULL;
    int64_t exp = 0;
    bool ok = auth_token_call(what, p, &acc, &ref, &exp, err, err_n);
    j_free(p);
    if (!ok) return false;

    login_t done = {current->name, acc, ref, exp, ""};
    if (!auth_store_login(&done, err, err_n)) {
        free(acc);
        free(ref);
        return false;
    }
    char id[256];
    auth_id_for_login(current->name, id, sizeof(id));
    auth_forget(id, err, err_n);

    auth_order_update(order_append_cb, (void *)current->name, err, err_n);

    if (!quiet) {
        hold_list_t empty = {0};
        sb_t line;
        sb_init(&line);
        auth_line(&done, &empty, now_ms(), &line);
        printf("%s\n", line.data);
        fflush(stdout);
        sb_free(&line);
    }
    free(acc);
    free(ref);
    return true;
}

bool auth_fresh(const login_t *l, login_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    if (l->expires - AUTH_MARGIN_MS > now_ms()) {
        out->name = xstrdup(l->name);
        out->access = xstrdup(l->access);
        out->refresh = xstrdup(l->refresh);
        out->expires = l->expires;
        out->verifier = xstrdup(l->verifier);
        return true;
    }

    char lock_path[1088];
    state_path("/logins.lock", lock_path, sizeof(lock_path));
    int fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) return false;

    login_list_t cur = {0};
    bool ok = auth_load(&cur, err, err_n);
    bool already_fresh = false;
    char *refresh_tok = NULL;
    if (ok) {
        login_t *found = NULL;
        for (size_t i = 0; i < cur.len; i++) {
            if (strcmp(cur.items[i].name, l->name) == 0) {
                found = &cur.items[i];
                break;
            }
        }
        if (!found) {
            snprintf(err, err_n, "login %s was removed while it waited to refresh", l->name);
            ok = false;
        } else if (found->expires - AUTH_MARGIN_MS > now_ms()) {
            out->name = xstrdup(found->name);
            out->access = xstrdup(found->access);
            out->refresh = xstrdup(found->refresh);
            out->expires = found->expires;
            out->verifier = xstrdup(found->verifier);
            already_fresh = true;
        } else {
            refresh_tok = xstrdup(found->refresh);
        }
    }
    login_list_free(&cur);
    file_unlock(fd);

    if (!ok || already_fresh) {
        free(refresh_tok);
        return ok;
    }

    jval_t *p = j_obj();
    j_obj_set(p, "grant_type", j_str("refresh_token"));
    j_obj_set(p, "client_id", j_str(AUTH_CLIENT_ID));
    j_obj_set(p, "refresh_token", j_str(refresh_tok));
    free(refresh_tok);
    char what[256];
    snprintf(what, sizeof(what), "login %s refresh", l->name);
    char *acc = NULL;
    char *ref = NULL;
    int64_t exp = 0;
    ok = auth_token_call(what, p, &acc, &ref, &exp, err, err_n);
    j_free(p);
    if (!ok) return false;

    fd = -1;
    if (!file_lock(lock_path, &fd, err, err_n)) {
        free(acc);
        free(ref);
        return false;
    }

    memset(&cur, 0, sizeof(cur));
    ok = auth_load(&cur, err, err_n);
    if (ok) {
        login_t *found = NULL;
        for (size_t i = 0; i < cur.len; i++) {
            if (strcmp(cur.items[i].name, l->name) == 0) {
                found = &cur.items[i];
                break;
            }
        }
        if (!found) {
            snprintf(err, err_n, "login %s was removed while refreshing", l->name);
            free(acc);
            free(ref);
            ok = false;
        } else {
            free(found->access);
            free(found->refresh);
            found->access = acc;
            found->refresh = ref;
            found->expires = exp;
            ok = auth_save(&cur, err, err_n);
            if (ok) {
                out->name = xstrdup(found->name);
                out->access = xstrdup(found->access);
                out->refresh = xstrdup(found->refresh);
                out->expires = found->expires;
                out->verifier = xstrdup(found->verifier);
            }
        }
    } else {
        free(acc);
        free(ref);
    }
    login_list_free(&cur);
    file_unlock(fd);
    return ok;
}

bool auth_login_interactive(const char *name, char *err, size_t err_n) {
    if (!auth_valid_name(name, err, err_n)) return false;
    bool is_l = false;
    if (!auth_is_login(name, &is_l, err, err_n)) return false;
    if (!is_l) {
        jval_t *e = NULL;
        if (!ak_get(name, &e, err, err_n)) return false;
        if (e) {
            j_free(e);
            snprintf(err, err_n, "a provider credential already uses %s", name);
            return false;
        }
    }
    char verifier[64];
    random_b64url(32, verifier);
    uint8_t dig[32];
    sha256_bytes((const uint8_t *)verifier, strlen(verifier), dig);
    char challenge[64];
    base64url_encode(dig, 32, challenge);

    int port = 53692;
    const char *penv = getenv("CREST_AUTH_PORT");
    if (penv && *penv) {
        int64_t pv = 0;
        if (str_to_i64(penv, &pv) && pv >= 0 && pv <= 65535) port = (int)pv;
    }

    int sock = -1, bound_port = 0;
    char lerr[256];
    if (!callback_open("127.0.0.1", port, &sock, &bound_port, lerr, sizeof(lerr))) {
        login_list_t cur = {0};
        login_t save = {(char *)name, "", "", 0, verifier};
        if (auth_load(&cur, err, err_n)) {
            for (size_t i = 0; i < cur.len; i++) {
                if (strcmp(cur.items[i].name, name) == 0) {
                    save = cur.items[i];
                    save.verifier = verifier;
                    break;
                }
            }
        }
        bool ok = auth_store_login(&save, err, err_n);
        login_list_free(&cur);
        if (!ok) return false;
        sb_t link;
        sb_init(&link);
        auth_link(AUTH_COPY_REDIRECT, challenge, verifier, &link);
        printf("The browser cannot call back here (%s), so sign in by copying the code instead.\n", lerr);
        printf("%s\n", link.data);
        printf("Open the link, sign in, then run: crest-auth login %s CODE\n", name);
        fflush(stdout);
        sb_free(&link);
        return true;
    }

    char redirect[128];
    snprintf(redirect, sizeof(redirect), "http://localhost:%d%s", bound_port, AUTH_CALLBACK_PATH);
    sb_t link;
    sb_init(&link);
    auth_link(redirect, challenge, verifier, &link);
    printf("%s\n", link.data);
    printf("Open the link to sign in. If the browser is on another machine, paste the address it ends on here.\n");
    fflush(stdout);
    sb_free(&link);

    char query[4096];
    bool from_stdin = false, timed_out = false;
    bool ok = callback_wait(sock, AUTH_CALLBACK_PATH, AUTH_PAGE, AUTH_WAIT_MS, true,
                            query, sizeof(query), &from_stdin, &timed_out, err, err_n);
    close(sock);
    if (!ok) return false;
    if (timed_out) {
        snprintf(err, err_n, "nothing arrived in %d minutes; run crest-auth login %s again",
                 (int)(AUTH_WAIT_MS / 60000), name);
        return false;
    }
    char code[512], state[512];
    if (!auth_code_parse(query, verifier, code, sizeof(code), state, sizeof(state), err, err_n)) {
        return false;
    }
    login_t blank = {(char *)name, "", "", 0, verifier};
    return auth_complete(&blank, code, state, redirect, false, err, err_n);
}

bool oa_load(const char *name, oa_tok_t *out, bool *found, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    *found = false;
    jval_t *entry = NULL;
    if (!ak_get(name, &entry, err, err_n)) return false;
    if (!entry) return true;
    if (strcmp(j_str_at(entry, "type"), "oauth") != 0) {
        j_free(entry);
        return true;
    }
    out->access = xstrdup(j_str_at(entry, "access"));
    out->refresh = xstrdup(j_str_at(entry, "refresh"));
    j_int_at(entry, "expires", &out->expires);
    out->extra = j_obj();
    for (size_t i = 0; i < entry->obj_len; i++) {
        const char *k = entry->obj[i].key;
        if (strcmp(k, "type") == 0 || strcmp(k, "provider") == 0 ||
            strcmp(k, "access") == 0 || strcmp(k, "refresh") == 0 || strcmp(k, "expires") == 0) {
            continue;
        }
        if (entry->obj[i].val->type == J_STR) {
            j_obj_set(out->extra, k, j_str(entry->obj[i].val->s));
        }
    }
    j_free(entry);
    *found = true;
    return true;
}

bool oa_save_named(const char *provider, const char *name, const oa_tok_t *t, char *err, size_t err_n) {
    jval_t *e = j_obj();
    j_obj_set(e, "provider", j_str(provider));
    j_obj_set(e, "type", j_str("oauth"));
    j_obj_set(e, "access", j_str(t->access));
    j_obj_set(e, "refresh", j_str(t->refresh));
    j_obj_set(e, "expires", j_int(t->expires));
    if (t->extra && t->extra->type == J_OBJ) {
        for (size_t i = 0; i < t->extra->obj_len; i++) {
            j_obj_set(e, t->extra->obj[i].key, j_clone(t->extra->obj[i].val));
        }
    }
    return ak_put(name, e, err, err_n);
}

bool oa_fresh(const oa_tok_t *t, int64_t now) {
    return t->access && t->access[0] && (t->expires == 0 || (t->expires - 60000) > now);
}

static const char *device_url_for(const char *provider) {
    if (strcmp(provider, "xai") == 0) return env_or("XAI_OAUTH_DEVICE_URL", "https://auth.x.ai/oauth/device/code");
    if (strcmp(provider, "kimi-coding") == 0) return env_or("KIMI_OAUTH_DEVICE_URL", "https://auth.kimi.com/api/oauth/device_authorization");
    if (strcmp(provider, "github-copilot") == 0) return env_or("COPILOT_OAUTH_DEVICE_URL", "https://github.com/login/device/code");
    if (strcmp(provider, "meta") == 0) return env_or("META_OAUTH_DEVICE_URL", "https://auth.meta.com/oauth/device/code");
    if (strcmp(provider, "qwen-oauth") == 0) return env_or("QWEN_OAUTH_DEVICE_URL", "https://chat.qwen.ai/api/v1/oauth2/device/code");
    if (strcmp(provider, "nous") == 0) return env_or("NOUS_OAUTH_DEVICE_URL", "https://portal.nousresearch.com/api/oauth/device");
    if (strcmp(provider, "minimax") == 0) return env_or("MINIMAX_OAUTH_DEVICE_URL", "https://api.minimax.io/oauth/code");
    return "";
}

static const char *token_url_for(const char *provider) {
    if (strcmp(provider, "xai") == 0) return env_or("XAI_OAUTH_TOKEN_URL", "https://auth.x.ai/oauth/token");
    if (strcmp(provider, "kimi-coding") == 0) return env_or("KIMI_OAUTH_TOKEN_URL", "https://auth.kimi.com/api/oauth/token");
    if (strcmp(provider, "github-copilot") == 0) return env_or("COPILOT_OAUTH_TOKEN_URL", "https://github.com/login/oauth/access_token");
    if (strcmp(provider, "meta") == 0) return env_or("META_OAUTH_TOKEN_URL", "https://auth.meta.com/oauth/token");
    if (strcmp(provider, "qwen-oauth") == 0) return env_or("QWEN_OAUTH_TOKEN_URL", "https://chat.qwen.ai/api/v1/oauth2/token");
    if (strcmp(provider, "nous") == 0) return env_or("NOUS_OAUTH_TOKEN_URL", "https://portal.nousresearch.com/api/oauth/token");
    if (strcmp(provider, "minimax") == 0) return env_or("MINIMAX_OAUTH_TOKEN_URL", "https://api.minimax.io/oauth/token");
    if (strcmp(provider, "openai-codex") == 0) return env_or("CODEX_OAUTH_TOKEN_URL", "https://auth.openai.com/oauth/token");
    if (strcmp(provider, "google-gemini-cli") == 0 || strcmp(provider, "google-antigravity") == 0)
        return env_or("GOOGLE_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token");
    return "";
}

static const char *client_id_for(const char *provider) {
    if (strcmp(provider, "xai") == 0) return "xai-cli";
    if (strcmp(provider, "kimi-coding") == 0) return "17e5f671-d194-4dfb-9706-5516cb48c098";
    if (strcmp(provider, "github-copilot") == 0) return "Iv1.b507a08c87ecfe98";
    if (strcmp(provider, "qwen-oauth") == 0) return "f0304373b74a44d2b584a3fb70ca9e56";
    if (strcmp(provider, "openai-codex") == 0) return "app_EMoamEEZ73f0CkXaXp7hrann";
    return provider;
}

bool oa_freshen_at(const char *name, const oa_tok_t *stored, int64_t at_ms, oa_tok_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    if (stored->access && stored->access[0] && (stored->expires == 0 || stored->expires > at_ms)) {
        out->access = xstrdup(stored->access);
        out->refresh = xstrdup(stored->refresh);
        out->expires = stored->expires;
        out->extra = j_clone(stored->extra);
        return true;
    }
    if (!stored->refresh || !stored->refresh[0]) {
        snprintf(err, err_n, "OAuth login %s has expired and has no refresh token", name);
        return false;
    }
    jval_t *entry = NULL;
    if (!ak_get(name, &entry, err, err_n)) return false;
    const char *prov = entry ? ak_provider(name, entry) : name;
    char prov_copy[128];
    snprintf(prov_copy, sizeof(prov_copy), "%s", prov);
    j_free(entry);

    const char *turl = token_url_for(prov_copy);
    if (!*turl) {
        snprintf(err, err_n, "%s: token refresh URL not configured", prov_copy);
        return false;
    }
    sb_t form;
    sb_init(&form);
    sb_puts(&form, "grant_type=refresh_token&client_id=");
    url_encode(client_id_for(prov_copy), &form);
    sb_puts(&form, "&refresh_token=");
    url_encode(stored->refresh, &form);

    const char *hdrs[2] = {
        "Content-Type: application/x-www-form-urlencoded",
        "Accept: application/json"
    };
    http_resp_t resp;
    char herr[256];
    bool ok = http_request("POST", turl, form.data, hdrs, 2, 120000, &resp, herr, sizeof(herr));
    sb_free(&form);
    if (!ok) {
        snprintf(err, err_n, "%s refresh: %s", name, herr);
        return false;
    }
    if (resp.status != 200) {
        snprintf(err, err_n, "%s refresh: HTTP %d: %s", name, resp.status, resp.body ? resp.body : "");
        http_resp_free(&resp);
        return false;
    }
    jval_t *j = j_parse(resp.body ? resp.body : "");
    http_resp_free(&resp);
    if (!j) {
        snprintf(err, err_n, "%s refresh: invalid JSON", name);
        return false;
    }
    const char *acc = j_str_at(j, "access_token");
    const char *ref = j_str_at(j, "refresh_token");
    int64_t secs = 3600;
    j_int_at(j, "expires_in", &secs);
    if (!*acc) {
        j_free(j);
        snprintf(err, err_n, "%s refresh: missing access_token", name);
        return false;
    }
    out->access = xstrdup(acc);
    out->refresh = xstrdup(*ref ? ref : stored->refresh);
    out->expires = now_ms() + secs * 1000;
    out->extra = j_clone(stored->extra);
    j_free(j);
    return oa_save_named(prov_copy, name, out, err, err_n);
}

static bool flows_read(jval_t **out, char *err, size_t err_n) {
    char path[1024];
    state_path("/flows.json", path, sizeof(path));
    char *text = NULL;
    bool nf = false;
    if (!file_read(path, &text, NULL, &nf)) {
        if (nf) {
            *out = j_obj();
            return true;
        }
        snprintf(err, err_n, "/flows.json: read failed");
        return false;
    }
    jval_t *j = j_parse(text);
    free(text);
    if (!j || j->type != J_OBJ) {
        j_free(j);
        *out = j_obj();
        return true;
    }
    *out = j;
    return true;
}

static bool flows_write(const jval_t *obj, char *err, size_t err_n) {
    char path[1024];
    state_path("/flows.json", path, sizeof(path));
    sb_t sb;
    sb_init(&sb);
    j_emit(obj, &sb);
    sb_putc(&sb, '\n');
    bool ok = file_write_0600(path, sb.data, sb.len);
    sb_free(&sb);
    if (!ok) snprintf(err, err_n, "/flows.json: write failed");
    return ok;
}

bool oa_flow_start_named(const char *provider, const char *name, oa_dev_t *out, char *err, size_t err_n) {
    memset(out, 0, sizeof(*out));
    const char *durl = device_url_for(provider);
    if (!*durl) {
        snprintf(err, err_n, "%s: no frontend sign-in flow yet; run crest-auth login %s", provider, provider);
        return false;
    }
    sb_t form;
    sb_init(&form);
    sb_puts(&form, "client_id=");
    url_encode(client_id_for(provider), &form);
    const char *hdrs[2] = {
        "Content-Type: application/x-www-form-urlencoded",
        "Accept: application/json"
    };
    http_resp_t resp;
    char herr[256];
    bool ok = http_request("POST", durl, form.data, hdrs, 2, 120000, &resp, herr, sizeof(herr));
    sb_free(&form);
    if (!ok) {
        snprintf(err, err_n, "%s: %s", provider, herr);
        return false;
    }
    if (resp.status != 200) {
        snprintf(err, err_n, "%s: HTTP %d: %s", provider, resp.status, resp.body ? resp.body : "");
        http_resp_free(&resp);
        return false;
    }
    jval_t *j = j_parse(resp.body ? resp.body : "");
    http_resp_free(&resp);
    if (!j) {
        snprintf(err, err_n, "%s: invalid JSON from device endpoint", provider);
        return false;
    }
    const char *dc = j_str_at(j, "device_code");
    const char *uc = j_str_at(j, "user_code");
    const char *uri = j_str_at(j, "verification_uri_complete");
    if (!*uri) uri = j_str_at(j, "verification_uri");
    int64_t interval = 5, exp_in = 600;
    j_int_at(j, "interval", &interval);
    j_int_at(j, "expires_in", &exp_in);
    snprintf(out->code, sizeof(out->code), "%s", dc);
    snprintf(out->user, sizeof(out->user), "%s", uc);
    snprintf(out->url, sizeof(out->url), "%s", uri);
    out->interval = interval > 0 ? interval : 5;
    out->expires = now_ms() + exp_in * 1000;
    j_free(j);

    jval_t *flows = NULL;
    if (!flows_read(&flows, err, err_n)) return false;
    jval_t *f = j_obj();
    j_obj_set(f, "provider", j_str(provider));
    j_obj_set(f, "code", j_str(out->code));
    j_obj_set(f, "user", j_str(out->user));
    j_obj_set(f, "url", j_str(out->url));
    j_obj_set(f, "interval", j_int(out->interval));
    j_obj_set(f, "expires", j_int(out->expires));
    j_obj_set(flows, name, f);
    ok = flows_write(flows, err, err_n);
    j_free(flows);
    return ok;
}

int oa_flow_poll(const char *name, int64_t *interval_out, char *err, size_t err_n) {
    *interval_out = 5;
    jval_t *flows = NULL;
    if (!flows_read(&flows, err, err_n)) return -1;
    jval_t *f = j_obj_get(flows, name);
    if (!f) {
        j_free(flows);
        snprintf(err, err_n, "no pending sign-in for %s", name);
        return -1;
    }
    char prov[128], dcode[256];
    snprintf(prov, sizeof(prov), "%s", j_str_at(f, "provider"));
    snprintf(dcode, sizeof(dcode), "%s", j_str_at(f, "code"));
    int64_t interval = 5, expires = 0;
    j_int_at(f, "interval", &interval);
    j_int_at(f, "expires", &expires);
    if (expires > 0 && now_ms() > expires) {
        j_obj_del(flows, name);
        flows_write(flows, err, err_n);
        j_free(flows);
        snprintf(err, err_n, "sign-in for %s expired", name);
        return -1;
    }

    const char *turl = token_url_for(prov);
    sb_t form;
    sb_init(&form);
    sb_puts(&form, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=");
    url_encode(client_id_for(prov), &form);
    sb_puts(&form, "&device_code=");
    url_encode(dcode, &form);
    const char *hdrs[2] = {
        "Content-Type: application/x-www-form-urlencoded",
        "Accept: application/json"
    };
    http_resp_t resp;
    char herr[256];
    bool ok = http_request("POST", turl, form.data, hdrs, 2, 120000, &resp, herr, sizeof(herr));
    sb_free(&form);
    if (!ok) {
        j_free(flows);
        snprintf(err, err_n, "%s", herr);
        return -1;
    }
    jval_t *j = j_parse(resp.body ? resp.body : "");
    int status = resp.status;
    http_resp_free(&resp);
    if (!j) {
        j_free(flows);
        snprintf(err, err_n, "HTTP %d: invalid JSON", status);
        return -1;
    }
    const char *ec = j_str_at(j, "error");
    if (strcmp(ec, "authorization_pending") == 0) {
        *interval_out = interval;
        j_free(j);
        j_free(flows);
        return 0;
    }
    if (strcmp(ec, "slow_down") == 0) {
        interval += 5;
        j_obj_set(f, "interval", j_int(interval));
        flows_write(flows, err, err_n);
        *interval_out = interval;
        j_free(j);
        j_free(flows);
        return 0;
    }
    if (*ec || status != 200) {
        snprintf(err, err_n, "%s", *ec ? ec : "token poll failed");
        j_obj_del(flows, name);
        flows_write(flows, err, err_n);
        j_free(j);
        j_free(flows);
        return -1;
    }
    oa_tok_t tok = {0};
    tok.access = xstrdup(j_str_at(j, "access_token"));
    tok.refresh = xstrdup(j_str_at(j, "refresh_token"));
    int64_t secs = 3600;
    j_int_at(j, "expires_in", &secs);
    tok.expires = now_ms() + secs * 1000;
    tok.extra = j_obj();
    j_free(j);

    ok = oa_save_named(prov, name, &tok, err, err_n);
    oa_tok_free(&tok);
    j_obj_del(flows, name);
    flows_write(flows, err, err_n);
    j_free(flows);
    return ok ? 1 : -1;
}

bool oa_login_named_interactive(const char *provider, const char *name, char *err, size_t err_n) {
    if (strcmp(oa_flow_kind(provider), "device") != 0) {
        snprintf(err, err_n, "%s: interactive browser login not implemented in this build", provider);
        return false;
    }
    oa_dev_t dev;
    if (!oa_flow_start_named(provider, name, &dev, err, err_n)) return false;
    printf("Open %s and enter code: %s\n", dev.url, dev.user);
    fflush(stdout);
    for (;;) {
        int64_t interval = dev.interval;
        int r = oa_flow_poll(name, &interval, err, err_n);
        if (r < 0) return false;
        if (r == 1) return true;
        sleep_ms(interval * 1000);
    }
}
