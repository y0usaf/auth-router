#define _POSIX_C_SOURCE 200809L

#include "quota.h"
#include "daemon.h"
#include "http.h"
#include "oauth.h"
#include "store.h"
#include "util.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define Q_MAX 32
#define Q_ROW_MAX (256 * 1024)
#define Q_HTTP_MS 15000
#define Q_DEADLINE_MS 20000
#define Q_MIN_MS 120000
#define Q_ANTHROPIC_MIN_MS 300000
#define Q_LIMITED_MIN_MS 600000
#define Q_BACKOFF_CAP_MS 3600000
#define Q_UNSUPPORTED_MS 3600000
#define Q_FAMILIES 64

typedef struct {
    char id[256];
    jval_t *row;
    int64_t next_ms;
    int64_t fails;
} qcache_t;

typedef struct {
    char err[320];
    int64_t retry_s;
    bool limited;
} qerr_t;

static qcache_t g_cache[Q_MAX];
static size_t g_cache_len;
static pid_t g_orphans[Q_MAX * 4];
static size_t g_orphan_len;

static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static int64_t env_ms(const char *name, int64_t fallback) {
    const char *v = getenv(name);
    int64_t n = 0;
    if (v && *v && str_to_i64(v, &n) && n >= 0) return n;
    return fallback;
}

static int64_t min_interval(const char *provider) {
    int64_t all = env_ms("AUTH_ROUTER_QUOTA_MIN_MS", -1);
    if (all >= 0) return all;
    return strcmp(provider, "anthropic") == 0 ? Q_ANTHROPIC_MIN_MS : Q_MIN_MS;
}

static int64_t days_civil(int64_t y, int64_t m, int64_t d) {
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static bool digits(const char *s, int n, int64_t *out) {
    int64_t v = 0;
    for (int i = 0; i < n; i++) {
        if (!isdigit((unsigned char)s[i])) return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

static int64_t iso_ms(const char *s) {
    int64_t y, mo, d, h, mi, se;
    if (strlen(s) < 19 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' ||
        s[16] != ':') {
        return 0;
    }
    if (!digits(s, 4, &y) || !digits(s + 5, 2, &mo) || !digits(s + 8, 2, &d) || !digits(s + 11, 2, &h) ||
        !digits(s + 14, 2, &mi) || !digits(s + 17, 2, &se)) {
        return 0;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return 0;
    const char *p = s + 19;
    int64_t frac = 0;
    if (*p == '.') {
        p++;
        int n = 0;
        while (isdigit((unsigned char)*p)) {
            if (n < 3) frac = frac * 10 + (*p - '0');
            n++;
            p++;
        }
        if (n == 0) return 0;
        for (; n < 3; n++) frac *= 10;
    }
    int64_t off = 0;
    if (*p == 'Z' || *p == 'z') {
        p++;
    } else if (*p == '+' || *p == '-') {
        int64_t oh, om;
        if (!digits(p + 1, 2, &oh)) return 0;
        const char *q = p + 3;
        if (*q == ':') q++;
        if (!digits(q, 2, &om)) return 0;
        off = (oh * 60 + om) * 60 * (*p == '-' ? -1 : 1);
        p = q + 2;
    }
    if (*p) return 0;
    int64_t ms = ((days_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se) - off) * 1000 + frac;
    return ms > 0 ? ms : 0;
}

static int64_t epoch_ms(int64_t n) {
    if (n <= 0) return 0;
    return n < 1000000000000LL ? n * 1000 : n;
}

static int64_t reset_value(const jval_t *v) {
    if (!v) return 0;
    if (v->type == J_INT) return epoch_ms(v->i);
    if (v->type == J_NUM) return (isfinite(v->d) && v->d > 0 && v->d < 1e15) ? epoch_ms((int64_t)v->d) : 0;
    if (v->type == J_STR) {
        int64_t n = 0;
        if (str_to_i64(v->s, &n)) return epoch_ms(n);
        return iso_ms(v->s);
    }
    return 0;
}

static bool num_value(const jval_t *v, double *out) {
    if (!v) return false;
    double d;
    if (v->type == J_INT) {
        d = (double)v->i;
    } else if (v->type == J_NUM) {
        d = v->d;
    } else if (v->type == J_STR) {
        char *end = NULL;
        errno = 0;
        d = strtod(v->s, &end);
        if (end == v->s || *end || errno) return false;
    } else {
        return false;
    }
    if (!isfinite(d)) return false;
    *out = d;
    return true;
}

static bool pct_value(const jval_t *v, double *out) {
    double d;
    if (!num_value(v, &d) || d < 0 || d > 1000) return false;
    *out = d;
    return true;
}

static int64_t retry_after_s(const char *v, int64_t now) {
    if (!v || !*v) return 0;
    int64_t n = 0;
    if (str_to_i64(v, &n)) return (n > 0 && n < 31536000) ? n : 0;
    static const char mons[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char wd[8], mon[8], tz[8];
    int dd, yy, hh, mm, ss;
    if (sscanf(v, "%7[A-Za-z], %d %7[A-Za-z] %d %d:%d:%d %7s", wd, &dd, mon, &yy, &hh, &mm, &ss, tz) != 8) return 0;
    if (strcmp(tz, "GMT") != 0 || strlen(mon) != 3) return 0;
    const char *m = strstr(mons, mon);
    if (!m || (m - mons) % 3 != 0) return 0;
    if (dd < 1 || dd > 31 || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60) return 0;
    int64_t at = days_civil(yy, (m - mons) / 3 + 1, dd) * 86400 + hh * 3600 + mm * 60 + ss;
    int64_t left = at - now / 1000;
    return (left > 0 && left < 31536000) ? left : 0;
}

static void window_put(jval_t *wins, const char *label, bool has_used, double used, int64_t reset_ms) {
    jval_t *w = j_obj();
    j_obj_set(w, "label", j_str(label));
    if (has_used) j_obj_set(w, "used", j_int((int64_t)llround(used)));
    if (reset_ms > 0) j_obj_set(w, "resets_ms", j_int(reset_ms));
    for (size_t i = 0; i < wins->arr_len; i++) {
        if (strcmp(j_str_at(wins->arr[i], "label"), label) == 0) {
            j_free(wins->arr[i]);
            wins->arr[i] = w;
            return;
        }
    }
    j_arr_push(wins, w);
}

static char *bearer(const char *tok) {
    sb_t sb;
    sb_init(&sb);
    sb_puts(&sb, "Authorization: Bearer ");
    sb_puts(&sb, tok ? tok : "");
    return sb.data;
}

static bool q_http(const char *method,
                   const char *url,
                   const char *body,
                   const char **hdrs,
                   size_t n,
                   http_resp_t *resp,
                   qerr_t *e) {
    char herr[256];
    herr[0] = '\0';
    if (!http_request(method, url, body, hdrs, n, env_ms("AUTH_ROUTER_QUOTA_HTTP_MS", Q_HTTP_MS), resp, herr,
                      sizeof(herr))) {
        snprintf(e->err, sizeof(e->err), "%s", herr[0] ? herr : "request failed");
        return false;
    }
    if (resp->status != 200) {
        int64_t ra = retry_after_s(resp->retry_after, now_ms());
        const char *why = (resp->status == 401 || resp->status == 403) ? " (token rejected)"
                          : resp->status == 429                         ? " (rate limited)"
                                                                        : "";
        e->retry_s = ra;
        e->limited = resp->status == 429;
        if (ra > 0) {
            snprintf(e->err, sizeof(e->err), "HTTP %d%s, retry after %llds", resp->status, why, (long long)ra);
        } else {
            snprintf(e->err, sizeof(e->err), "HTTP %d%s", resp->status, why);
        }
        http_resp_free(resp);
        return false;
    }
    return true;
}

static bool anth_shape(const jval_t *j) {
    for (size_t i = 0; i < j->obj_len; i++) {
        const char *k = j->obj[i].key;
        if (strcmp(k, "five_hour") == 0 || strcmp(k, "seven_day") == 0 || strcmp(k, "limits") == 0 ||
            strcmp(k, "spend") == 0 || strcmp(k, "extra_usage") == 0 || strncmp(k, "seven_day_", 10) == 0) {
            return true;
        }
    }
    return false;
}

static void anth_window(jval_t *wins, const char *label, const jval_t *o) {
    if (!o || o->type != J_OBJ || !j_obj_get(o, "utilization")) return;
    double u = 0;
    bool has = pct_value(j_obj_get(o, "utilization"), &u);
    window_put(wins, label, has, u, reset_value(j_obj_get(o, "resets_at")));
}

static void anth_limit(jval_t *wins, const jval_t *o) {
    if (!o || o->type != J_OBJ) return;
    const char *kind = j_str_at(o, "kind");
    double u = 0;
    bool has = pct_value(j_obj_get(o, "percent"), &u) || pct_value(j_obj_get(o, "utilization"), &u);
    const jval_t *rv = j_obj_get(o, "resets_at");
    int64_t reset = reset_value(rv ? rv : j_obj_get(o, "resetsAt"));
    char label[160];
    if (strcmp(kind, "session") == 0) {
        snprintf(label, sizeof(label), "5h");
    } else if (strcmp(kind, "weekly_all") == 0) {
        snprintf(label, sizeof(label), "7d");
    } else if (strcmp(kind, "weekly_scoped") == 0) {
        const jval_t *m = j_obj_get(j_obj_get(o, "scope"), "model");
        const char *name = "";
        if (m && m->type == J_STR) {
            name = m->s;
        } else if (m && m->type == J_OBJ) {
            name = j_str_at(m, "display_name")[0] ? j_str_at(m, "display_name") : j_str_at(m, "id");
        }
        if (!name[0]) return;
        snprintf(label, sizeof(label), "7d %.120s", name);
    } else {
        return;
    }
    window_put(wins, label, has, u, reset);
}

static void parse_anthropic(const char *body, jval_t *row, qerr_t *e) {
    jval_t *j = j_parse(body);
    if (!j || j->type != J_OBJ) {
        snprintf(e->err, sizeof(e->err), "the usage response was not JSON");
        j_free(j);
        return;
    }
    if (!anth_shape(j)) {
        snprintf(e->err, sizeof(e->err), "the usage response had an unexpected shape");
        j_free(j);
        return;
    }
    jval_t *wins = j_arr();
    for (size_t i = 0; i < j->obj_len; i++) {
        const char *k = j->obj[i].key;
        const jval_t *v = j->obj[i].val;
        char label[160];
        if (strcmp(k, "five_hour") == 0) {
            anth_window(wins, "5h", v);
        } else if (strcmp(k, "seven_day") == 0) {
            anth_window(wins, "7d", v);
        } else if (strncmp(k, "seven_day_", 10) == 0 && k[10]) {
            snprintf(label, sizeof(label), "7d %.120s", k + 10);
            anth_window(wins, label, v);
        }
    }
    const jval_t *limits = j_obj_get(j, "limits");
    if (limits && limits->type == J_ARR) {
        for (size_t i = 0; i < limits->arr_len; i++) anth_limit(wins, limits->arr[i]);
    }
    const jval_t *extra = j_obj_get(j, "extra_usage");
    const jval_t *en = j_obj_get(extra, "is_enabled");
    double xu = 0;
    if (en && en->type == J_BOOL && en->b && pct_value(j_obj_get(extra, "utilization"), &xu)) {
        window_put(wins, "monthly", true, xu, 0);
        double uc = 0, ml = 0;
        int64_t dp = 2;
        j_int_at(extra, "decimal_places", &dp);
        if (dp >= 0 && dp <= 6 && num_value(j_obj_get(extra, "used_credits"), &uc) &&
            num_value(j_obj_get(extra, "monthly_limit"), &ml)) {
            double scale = 1;
            for (int64_t i = 0; i < dp; i++) scale *= 10;
            char note[128];
            snprintf(note, sizeof(note), "%.12s %.2f/%.2f", j_str_at(extra, "currency"), uc / scale, ml / scale);
            j_obj_set(row, "note", j_str(note));
        }
    }
    if (j_str_at(j, "subscription_type")[0]) j_obj_set(row, "plan", j_str(j_str_at(j, "subscription_type")));
    j_obj_set(row, "windows", wins);
    j_free(j);
}

static void probe_anthropic(const cred_t *c, jval_t *row, qerr_t *e) {
    char err[512];
    err[0] = '\0';
    login_list_t logins;
    if (!auth_load(&logins, err, sizeof(err))) {
        snprintf(e->err, sizeof(e->err), "%.300s", err);
        return;
    }
    const login_t *found = NULL;
    for (size_t i = 0; i < logins.len; i++) {
        if (strcmp(logins.items[i].name, c->name) == 0) {
            found = &logins.items[i];
            break;
        }
    }
    if (!found) {
        login_list_free(&logins);
        snprintf(e->err, sizeof(e->err), "login not found");
        return;
    }
    if (!found->access[0] && !found->refresh[0]) {
        login_list_free(&logins);
        snprintf(e->err, sizeof(e->err), "the login was never finished");
        return;
    }
    login_t fresh;
    bool ok = auth_fresh(found, &fresh, err, sizeof(err));
    login_list_free(&logins);
    if (!ok) {
        snprintf(e->err, sizeof(e->err), "refresh failed: %.200s", err);
        return;
    }
    char *auth = bearer(fresh.access);
    free(fresh.name);
    free(fresh.access);
    free(fresh.refresh);
    free(fresh.verifier);
    const char *hdrs[5] = {
        auth,
        "anthropic-beta: oauth-2025-04-20",
        "Accept: application/json",
        "Content-Type: application/json",
        "User-Agent: " AUTH_AGENT
    };
    http_resp_t r;
    const char *url = env_or("AUTH_ROUTER_ANTHROPIC_USAGE_URL", "https://api.anthropic.com/api/oauth/usage");
    bool got = q_http("GET", url, NULL, hdrs, 5, &r, e);
    free(auth);
    if (!got) return;
    parse_anthropic(r.body ? r.body : "", row, e);
    http_resp_free(&r);
}

static void span_label(int64_t secs, char *out, size_t n) {
    if (secs % 86400 == 0) snprintf(out, n, "%lldd", (long long)(secs / 86400));
    else if (secs % 3600 == 0) snprintf(out, n, "%lldh", (long long)(secs / 3600));
    else snprintf(out, n, "%lldm", (long long)(secs / 60));
}

static bool codex_shape(const jval_t *j) {
    static const char *const keys[] = {
        "rate_limit", "plan_type", "credits", "spend_control", "additional_rate_limits"
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (j_obj_get(j, keys[i])) return true;
    }
    return false;
}

static void parse_codex(const char *body, jval_t *row, qerr_t *e) {
    jval_t *j = j_parse(body);
    if (!j || j->type != J_OBJ) {
        snprintf(e->err, sizeof(e->err), "the usage response was not JSON");
        j_free(j);
        return;
    }
    if (!codex_shape(j)) {
        snprintf(e->err, sizeof(e->err), "the usage response had an unexpected shape");
        j_free(j);
        return;
    }
    jval_t *wins = j_arr();
    const jval_t *rl = j_obj_get(j, "rate_limit");
    static const char *const names[2] = {"primary_window", "secondary_window"};
    int64_t now = now_ms();
    for (int k = 0; k < 2; k++) {
        const jval_t *w = j_obj_get(rl, names[k]);
        if (!w || w->type != J_OBJ) continue;
        int64_t secs = 0;
        double secs_d = 0;
        if (num_value(j_obj_get(w, "limit_window_seconds"), &secs_d) && secs_d > 0 && secs_d < 1e9) {
            secs = (int64_t)secs_d;
        }
        char label[32];
        if (secs >= 60) span_label(secs, label, sizeof(label));
        else snprintf(label, sizeof(label), "%s", k == 0 ? "primary" : "secondary");
        double u = 0;
        bool has = pct_value(j_obj_get(w, "used_percent"), &u);
        int64_t reset = reset_value(j_obj_get(w, "reset_at"));
        double after = 0;
        if (!reset && num_value(j_obj_get(w, "reset_after_seconds"), &after) && after > 0 && after < 1e9) {
            reset = now + (int64_t)after * 1000;
        }
        window_put(wins, label, has, u, reset);
    }
    const jval_t *sc = j_obj_get(j, "spend_control");
    const jval_t *il = j_obj_get(sc, "individual_limit");
    if (il && il->type == J_OBJ) {
        double u = 0, used = 0, lim = 0;
        bool nums = num_value(j_obj_get(il, "used"), &used) && num_value(j_obj_get(il, "limit"), &lim) && lim > 0;
        bool has = pct_value(j_obj_get(il, "used_percent"), &u);
        if (!has && nums && used >= 0 && used / lim <= 10) {
            u = used / lim * 100.0;
            has = true;
        }
        int64_t reset = reset_value(j_obj_get(il, "reset_at"));
        double after = 0;
        if (!reset && num_value(j_obj_get(il, "reset_after_seconds"), &after) && after > 0 && after < 1e9) {
            reset = now + (int64_t)after * 1000;
        }
        window_put(wins, "spend", has, u, reset);
        const jval_t *reached = j_obj_get(sc, "reached");
        bool hit = reached && reached->type == J_BOOL && reached->b;
        if (nums) {
            char note[128];
            const char *unit = j_str_at(il, "unit");
            snprintf(note, sizeof(note), "%.0f/%.0f %.16s%s%s", used, lim, unit[0] ? unit : "credit",
                     unit[0] && strcmp(unit, "credit") != 0 ? "" : "s", hit ? " · limit reached" : "");
            j_obj_set(row, "note", j_str(note));
        } else if (hit) {
            j_obj_set(row, "note", j_str("limit reached"));
        }
    }
    if (j_str_at(j, "plan_type")[0]) j_obj_set(row, "plan", j_str(j_str_at(j, "plan_type")));
    j_obj_set(row, "windows", wins);
    j_free(j);
}

static void probe_codex(const cred_t *c, jval_t *row, qerr_t *e) {
    char err[512];
    err[0] = '\0';
    oa_tok_t tok;
    bool found = false;
    if (!oa_load(c->name, &tok, &found, err, sizeof(err))) {
        snprintf(e->err, sizeof(e->err), "%.300s", err);
        return;
    }
    if (!found) {
        snprintf(e->err, sizeof(e->err), "no OAuth credential stored");
        return;
    }
    oa_tok_t fresh;
    bool ok = oa_freshen_at(c->name, &tok, now_ms() + 60000, &fresh, err, sizeof(err));
    oa_tok_free(&tok);
    if (!ok) {
        snprintf(e->err, sizeof(e->err), "refresh failed: %.200s", err);
        return;
    }
    char *auth = bearer(fresh.access);
    sb_t acct;
    sb_init(&acct);
    const char *aid = j_str_at(fresh.extra, "account_id");
    if (aid[0]) {
        sb_puts(&acct, "chatgpt-account-id: ");
        sb_puts(&acct, aid);
    }
    oa_tok_free(&fresh);
    sb_t url;
    sb_init(&url);
    const char *base = env_or("CODEX_BASE_URL", "https://chatgpt.com/backend-api/codex");
    size_t bl = strlen(base);
    while (bl > 0 && base[bl - 1] == '/') bl--;
    if (bl >= 6 && strncmp(base + bl - 6, "/codex", 6) == 0) bl -= 6;
    sb_putn(&url, base, bl);
    sb_puts(&url, "/wham/usage");
    const char *hdrs[6];
    size_t n = 0;
    hdrs[n++] = auth;
    if (acct.data && acct.len) hdrs[n++] = acct.data;
    hdrs[n++] = "originator: pi";
    hdrs[n++] = "User-Agent: pi (crest)";
    hdrs[n++] = "OpenAI-Beta: responses=experimental";
    hdrs[n++] = "Accept: application/json";
    http_resp_t r;
    bool got = q_http("GET", url.data, NULL, hdrs, n, &r, e);
    free(auth);
    sb_free(&acct);
    sb_free(&url);
    if (!got) return;
    parse_codex(r.body ? r.body : "", row, e);
    http_resp_free(&r);
}

static void credit_text(const jval_t *v, char *out, size_t n) {
    out[0] = '\0';
    double d = 0;
    if (!num_value(v, &d)) return;
    snprintf(out, n, "%.2f", d);
}

static void probe_vercel(const cred_t *c, jval_t *row, qerr_t *e) {
    char err[512];
    err[0] = '\0';
    jval_t *entry = NULL;
    if (!ak_get(c->name, &entry, err, sizeof(err))) {
        snprintf(e->err, sizeof(e->err), "%.300s", err);
        return;
    }
    const char *key = j_str_at(entry, "key");
    if (!key[0]) {
        j_free(entry);
        snprintf(e->err, sizeof(e->err), "no API key stored");
        return;
    }
    char *auth = bearer(key);
    j_free(entry);
    sb_t url;
    sb_init(&url);
    sb_puts(&url, env_or("AUTH_ROUTER_VERCEL_BASE", "https://ai-gateway.vercel.sh"));
    sb_puts(&url, "/v1/credits");
    const char *hdrs[5] = {
        auth,
        "ai-gateway-auth-method: api-key",
        "ai-gateway-protocol-version: 0.0.1",
        "Accept: application/json",
        "User-Agent: auth-router/0.1"
    };
    http_resp_t r;
    bool got = q_http("GET", url.data, NULL, hdrs, 5, &r, e);
    free(auth);
    sb_free(&url);
    if (!got) return;
    jval_t *j = j_parse(r.body ? r.body : "");
    http_resp_free(&r);
    if (!j || j->type != J_OBJ || (!j_obj_get(j, "balance") && !j_obj_get(j, "total_used"))) {
        snprintf(e->err, sizeof(e->err), "the credits response had an unexpected shape");
        j_free(j);
        return;
    }
    char bal[64], used[64];
    credit_text(j_obj_get(j, "balance"), bal, sizeof(bal));
    credit_text(j_obj_get(j, "total_used"), used, sizeof(used));
    if (bal[0]) j_obj_set(row, "balance", j_str(bal));
    if (used[0]) j_obj_set(row, "total_used", j_str(used));
    j_obj_set(row, "windows", j_arr());
    j_free(j);
}

static void agy_root(char *out, size_t n) {
    const char *over = getenv("AUTH_ROUTER_AGY_ROOT");
    if (over && *over) {
        snprintf(out, n, "%s", over);
        return;
    }
    const char *xdg = getenv("XDG_DATA_HOME");
    if (xdg && *xdg) {
        snprintf(out, n, "%s/omp/antigravity-cli", xdg);
        return;
    }
    const char *home = getenv("HOME");
    snprintf(out, n, "%s/.local/share/omp/antigravity-cli", home ? home : "");
}

static bool agy_token(const char *email, char **access, int64_t *expires, char *err, size_t err_n) {
    char root[1024];
    agy_root(root, sizeof(root));
    DIR *d1 = opendir(root);
    if (!d1) {
        snprintf(err, err_n, "no Antigravity logins under %.200s", root);
        return false;
    }
    int64_t best_mtime = -1;
    struct dirent *a;
    while ((a = readdir(d1)) != NULL) {
        if (a->d_name[0] == '.') continue;
        char p1[2048];
        snprintf(p1, sizeof(p1), "%s/%s", root, a->d_name);
        DIR *d2 = opendir(p1);
        if (!d2) continue;
        struct dirent *b;
        while ((b = readdir(d2)) != NULL) {
            if (b->d_name[0] == '.') continue;
            char p2[4096];
            snprintf(p2, sizeof(p2), "%s/%s/antigravity-cli/antigravity-oauth-token", p1, b->d_name);
            struct stat st;
            if (stat(p2, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 65536) continue;
            int64_t mt = (int64_t)st.st_mtime;
            if (mt <= best_mtime) continue;
            char *text = NULL;
            if (!file_read(p2, &text, NULL, NULL)) continue;
            jval_t *j = j_parse(text ? text : "");
            free(text);
            const jval_t *t = j_obj_get(j, "token");
            const char *acc = j_str_at(t, "access_token");
            if (strcasecmp(j_str_at(j, "id_token_email"), email) == 0 && acc[0]) {
                free(*access);
                *access = strdup(acc);
                if (!*access) abort();
                *expires = iso_ms(j_str_at(t, "expiry"));
                best_mtime = mt;
            }
            j_free(j);
        }
        closedir(d2);
    }
    closedir(d1);
    if (best_mtime < 0) {
        snprintf(err, err_n, "no Antigravity login for %.200s", email);
        return false;
    }
    return true;
}

static void model_family(const char *id, char *out, size_t n) {
    static const char *const efforts[] = {"low", "medium", "high", "xhigh", "tiered"};
    snprintf(out, n, "%s", id);
    for (;;) {
        char *dash = strrchr(out, '-');
        if (!dash || dash == out) return;
        bool hit = false;
        for (size_t i = 0; i < sizeof(efforts) / sizeof(efforts[0]); i++) {
            if (strcmp(dash + 1, efforts[i]) == 0) hit = true;
        }
        if (!hit) return;
        *dash = '\0';
    }
}

static void parse_models(const char *body, jval_t *row, qerr_t *e) {
    jval_t *j = j_parse(body);
    if (!j || j->type != J_OBJ) {
        snprintf(e->err, sizeof(e->err), "the quota response was not JSON");
        j_free(j);
        return;
    }
    char fam[Q_FAMILIES][128];
    double used[Q_FAMILIES];
    int64_t reset[Q_FAMILIES];
    size_t nf = 0;
    const jval_t *buckets = j_obj_get(j, "buckets");
    for (size_t i = 0; buckets && buckets->type == J_ARR && i < buckets->arr_len; i++) {
        const jval_t *b = buckets->arr[i];
        const char *model = j_str_at(b, "modelId");
        int64_t at = iso_ms(j_str_at(b, "resetTime"));
        const jval_t *rfv = j_obj_get(b, "remainingFraction");
        double rf = 0;
        if (rfv && !num_value(rfv, &rf)) continue;
        if (!model[0] || at <= 0 || rf < 0 || rf > 1) continue;
        char f[128];
        model_family(model, f, sizeof(f));
        double u = (1.0 - rf) * 100.0;
        size_t k = 0;
        while (k < nf && strcmp(fam[k], f) != 0) k++;
        if (k == nf) {
            if (nf == Q_FAMILIES) continue;
            snprintf(fam[k], sizeof(fam[k]), "%s", f);
            used[k] = u;
            reset[k] = at;
            nf++;
        } else {
            if (u > used[k]) used[k] = u;
            if (at < reset[k]) reset[k] = at;
        }
    }
    jval_t *wins = j_arr();
    for (size_t k = 0; k < nf; k++) window_put(wins, fam[k], true, used[k], reset[k]);
    j_obj_set(row, "windows", wins);
    j_free(j);
}

static void probe_antigravity(const cred_t *c, jval_t *row, qerr_t *e) {
    char email[256];
    if (!acp_email(c->name, email, sizeof(email))) {
        snprintf(e->err, sizeof(e->err), "the account names no Google login");
        return;
    }
    char err[512];
    err[0] = '\0';
    char *access = NULL;
    int64_t expires = 0;
    if (!agy_token(email, &access, &expires, err, sizeof(err))) {
        snprintf(e->err, sizeof(e->err), "%.300s", err);
        return;
    }
    if (expires > 0 && expires - 60000 <= now_ms()) {
        free(access);
        snprintf(e->err, sizeof(e->err), "the agy token expired; agy refreshes it on its next use");
        return;
    }
    char *auth = bearer(access);
    free(access);
    sb_t url;
    sb_init(&url);
    sb_puts(&url, env_or("GOOGLE_ANTIGRAVITY_URL", "https://daily-cloudcode-pa.googleapis.com"));
    sb_puts(&url, "/v1internal:retrieveUserQuota");
    sb_t ua;
    sb_init(&ua);
    sb_puts(&ua, "User-Agent: antigravity/hub/");
    sb_puts(&ua, env_or("GOOGLE_ANTIGRAVITY_VERSION", "2.24.0"));
    sb_puts(&ua, " (aidev_client; os_type=darwin; arch=arm64; cl=1000335682)");
    const char *hdrs[4] = {auth, "Content-Type: application/json", "Accept: text/event-stream", ua.data};
    http_resp_t r;
    bool got = q_http("POST", url.data, "{}", hdrs, 4, &r, e);
    free(auth);
    sb_free(&url);
    sb_free(&ua);
    if (!got) return;
    parse_models(r.body ? r.body : "", row, e);
    http_resp_free(&r);
}

static void row_ident(jval_t *row, const cred_t *c) {
    j_obj_set(row, "id", j_str(c->id));
    j_obj_set(row, "name", j_str(c->name));
    j_obj_set(row, "provider", j_str(c->provider));
    j_obj_set(row, "kind", j_str(c->kind));
}

static int64_t backoff_ms(int64_t minv, int64_t fails) {
    int64_t back = minv;
    for (int64_t i = 1; i < fails && i < 6 && back < Q_BACKOFF_CAP_MS; i++) back *= 2;
    return back > Q_BACKOFF_CAP_MS ? Q_BACKOFF_CAP_MS : back;
}

static void row_finish(jval_t *row, const char *provider, const char *status, const qerr_t *e, int64_t prev_fails) {
    int64_t now = now_ms();
    int64_t minv = min_interval(provider);
    int64_t fails = 0;
    int64_t wait = minv;
    if (strcmp(status, "unsupported") == 0) {
        wait = Q_UNSUPPORTED_MS;
    } else if (strcmp(status, "error") == 0) {
        fails = prev_fails + 1;
        wait = backoff_ms(minv, fails);
        if (e && e->limited && !e->retry_s && wait < Q_LIMITED_MIN_MS) wait = Q_LIMITED_MIN_MS;
        if (e && e->retry_s * 1000 > wait) wait = e->retry_s * 1000;
    }
    j_obj_set(row, "status", j_str(status));
    if (e && e->err[0]) j_obj_set(row, "error", j_str(e->err));
    if (e && e->retry_s > 0) j_obj_set(row, "retry_after_s", j_int(e->retry_s));
    if (!j_obj_get(row, "windows")) j_obj_set(row, "windows", j_arr());
    j_obj_set(row, "fetched_ms", j_int(now));
    j_obj_set(row, "next_ms", j_int(now + wait));
    j_obj_set(row, "fails", j_int(fails));
}

static jval_t *probe_one(const cred_t *c, int64_t prev_fails) {
    jval_t *row = j_obj();
    row_ident(row, c);
    qerr_t e;
    memset(&e, 0, sizeof(e));
    bool supported = true;
    if (strcmp(c->kind, "login") == 0) {
        probe_anthropic(c, row, &e);
    } else if (strcmp(c->kind, "oauth") == 0 && strcmp(c->provider, "openai-codex") == 0) {
        probe_codex(c, row, &e);
    } else if (strcmp(c->kind, "api_key") == 0 && strcmp(c->provider, "vercel-ai-gateway") == 0) {
        probe_vercel(c, row, &e);
    } else if (strcmp(c->kind, "acp") == 0) {
        probe_antigravity(c, row, &e);
    } else {
        supported = false;
        snprintf(e.err, sizeof(e.err), "no quota endpoint for %s %s", c->provider, c->kind);
    }
    if (e.err[0]) j_obj_del(row, "windows");
    row_finish(row, c->provider, !supported ? "unsupported" : e.err[0] ? "error" : "ok", &e, prev_fails);
    return row;
}

static jval_t *row_fail(const cred_t *c, const char *msg, int64_t prev_fails) {
    jval_t *row = j_obj();
    row_ident(row, c);
    qerr_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.err, sizeof(e.err), "%s", msg);
    row_finish(row, c->provider, "error", &e, prev_fails);
    return row;
}

static qcache_t *cache_find(const char *id) {
    for (size_t i = 0; i < g_cache_len; i++) {
        if (strcmp(g_cache[i].id, id) == 0) return &g_cache[i];
    }
    return NULL;
}

static void close_fds_except(int keep) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            int fd = atoi(de->d_name);
            if (fd > 2 && fd != keep && fd != dfd) close(fd);
        }
        closedir(d);
        return;
    }
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
    for (int fd = 3; fd < (int)max_fd; fd++) {
        if (fd != keep) close(fd);
    }
}

static void write_all(int fd, const char *s, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void orphan(pid_t pid) {
    if (g_orphan_len < sizeof(g_orphans) / sizeof(g_orphans[0])) g_orphans[g_orphan_len++] = pid;
}

static void reap_orphans(void) {
    size_t k = 0;
    for (size_t i = 0; i < g_orphan_len; i++) {
        int st = 0;
        if (waitpid(g_orphans[i], &st, WNOHANG) == 0) g_orphans[k++] = g_orphans[i];
    }
    g_orphan_len = k;
}

jval_t *quota_collect(void) {
    reap_orphans();
    char err[512];
    err[0] = '\0';
    cred_list_t creds;
    if (!auth_credentials(&creds, err, sizeof(err))) {
        jval_t *r = j_obj();
        j_obj_set(r, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(r, "ok", j_bool(false));
        j_obj_set(r, "error", j_str(err[0] ? err : "could not read credentials"));
        return r;
    }
    size_t n = creds.len > Q_MAX ? Q_MAX : creds.len;
    jval_t *rows[Q_MAX];
    pid_t pids[Q_MAX];
    int fds[Q_MAX];
    sb_t bufs[Q_MAX];
    bool live[Q_MAX];
    bool bad[Q_MAX];
    int64_t fails[Q_MAX];
    int64_t now = now_ms();
    for (size_t i = 0; i < n; i++) {
        const cred_t *c = &creds.items[i];
        rows[i] = NULL;
        pids[i] = -1;
        fds[i] = -1;
        sb_init(&bufs[i]);
        live[i] = false;
        bad[i] = false;
        fails[i] = 0;
        qcache_t *ce = cache_find(c->id);
        if (ce) fails[i] = ce->fails;
        if (ce && ce->row && now < ce->next_ms) {
            rows[i] = j_clone(ce->row);
            j_obj_set(rows[i], "cached", j_bool(true));
            continue;
        }
        int pfd[2];
        if (pipe(pfd) != 0) {
            rows[i] = row_fail(c, "could not start the probe", fails[i]);
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
            close(pfd[0]);
            close(pfd[1]);
            rows[i] = row_fail(c, "could not start the probe", fails[i]);
            continue;
        }
        if (pid == 0) {
            setsid();
            signal(SIGPIPE, SIG_IGN);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            int wfd = pfd[1] > STDERR_FILENO ? pfd[1] : fcntl(pfd[1], F_DUPFD, STDERR_FILENO + 1);
            if (wfd < 0) _exit(1);
            int nul = open("/dev/null", O_RDWR);
            if (nul >= 0) {
                dup2(nul, STDIN_FILENO);
                dup2(nul, STDOUT_FILENO);
                dup2(nul, STDERR_FILENO);
                if (nul > STDERR_FILENO) close(nul);
            }
            close_fds_except(wfd);
            jval_t *row = probe_one(c, fails[i]);
            char *s = j_show(row);
            if (s) write_all(wfd, s, strlen(s));
            _exit(0);
        }
        close(pfd[1]);
        int fl = fcntl(pfd[0], F_GETFL, 0);
        if (fl >= 0) fcntl(pfd[0], F_SETFL, fl | O_NONBLOCK);
        fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
        pids[i] = pid;
        fds[i] = pfd[0];
        live[i] = true;
    }

    int64_t limit = env_ms("AUTH_ROUTER_QUOTA_TIMEOUT_MS", Q_DEADLINE_MS);
    int64_t deadline = now_ms() + limit;
    for (;;) {
        struct pollfd pf[Q_MAX];
        size_t map[Q_MAX];
        nfds_t k = 0;
        for (size_t i = 0; i < n; i++) {
            if (!live[i]) continue;
            pf[k].fd = fds[i];
            pf[k].events = POLLIN;
            pf[k].revents = 0;
            map[k++] = i;
        }
        if (k == 0) break;
        int64_t rem = deadline - now_ms();
        if (rem <= 0) break;
        int pr = poll(pf, k, rem > 1000 ? 1000 : (int)rem);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (nfds_t q = 0; q < k; q++) {
            if (!pf[q].revents) continue;
            size_t i = map[q];
            char buf[4096];
            for (;;) {
                ssize_t r = read(fds[i], buf, sizeof(buf));
                if (r > 0) {
                    if (bufs[i].len + (size_t)r > Q_ROW_MAX) {
                        bad[i] = true;
                        live[i] = false;
                        break;
                    }
                    sb_putn(&bufs[i], buf, (size_t)r);
                    continue;
                }
                if (r == 0) {
                    live[i] = false;
                    break;
                }
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    bad[i] = true;
                    live[i] = false;
                }
                break;
            }
        }
    }

    jval_t *res = j_obj();
    j_obj_set(res, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
    j_obj_set(res, "ok", j_bool(true));
    j_obj_set(res, "now_ms", j_int(now_ms()));
    jval_t *accounts = j_arr();
    for (size_t i = 0; i < n; i++) {
        const cred_t *c = &creds.items[i];
        if (fds[i] >= 0) close(fds[i]);
        if (!rows[i]) {
            if (live[i]) {
                char msg[96];
                snprintf(msg, sizeof(msg), "timed out after %llds", (long long)((limit + 999) / 1000));
                rows[i] = row_fail(c, msg, fails[i]);
            } else {
                jval_t *r = (!bad[i] && bufs[i].data) ? j_parse(bufs[i].data) : NULL;
                if (!r || r->type != J_OBJ || strcmp(j_str_at(r, "id"), c->id) != 0) {
                    j_free(r);
                    r = row_fail(c, "the probe exited without a result", fails[i]);
                }
                rows[i] = r;
            }
        }
        if (pids[i] > 0) {
            int st = 0;
            if (waitpid(pids[i], &st, WNOHANG) == 0) orphan(pids[i]);
        }
        sb_free(&bufs[i]);
        j_arr_push(accounts, rows[i]);
    }
    j_obj_set(res, "accounts", accounts);
    cred_list_free(&creds);
    return res;
}

void quota_cache_absorb(const jval_t *res) {
    const jval_t *ok = j_obj_get(res, "ok");
    const jval_t *acc = j_obj_get(res, "accounts");
    if (!ok || ok->type != J_BOOL || !ok->b || !acc || acc->type != J_ARR) return;
    qcache_t next[Q_MAX];
    size_t nn = 0;
    for (size_t i = 0; i < acc->arr_len && nn < Q_MAX; i++) {
        const jval_t *row = acc->arr[i];
        const char *id = j_str_at(row, "id");
        if (!id[0] || strlen(id) >= sizeof(next[nn].id)) continue;
        bool dup = false;
        for (size_t k = 0; k < nn; k++) {
            if (strcmp(next[k].id, id) == 0) dup = true;
        }
        if (dup) continue;
        const jval_t *cached = j_obj_get(row, "cached");
        if (cached && cached->type == J_BOOL && cached->b) {
            qcache_t *old = cache_find(id);
            if (old && old->row) {
                next[nn] = *old;
                old->row = NULL;
                nn++;
            }
            continue;
        }
        memset(&next[nn], 0, sizeof(next[nn]));
        snprintf(next[nn].id, sizeof(next[nn].id), "%s", id);
        next[nn].row = j_clone(row);
        j_obj_del(next[nn].row, "cached");
        j_int_at(row, "next_ms", &next[nn].next_ms);
        j_int_at(row, "fails", &next[nn].fails);
        nn++;
    }
    for (size_t i = 0; i < g_cache_len; i++) j_free(g_cache[i].row);
    memcpy(g_cache, next, nn * sizeof(next[0]));
    g_cache_len = nn;
}
