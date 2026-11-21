#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "daemon.h"
#include "json.h"
#include "quota.h"
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define ATOP_RPC_MS 45000
#define ATOP_LINES 256
#define ATOP_BAR 10
#define HIST_CAP 240
#define HIST_MAX 160
#define HIST_TTL_MS (30LL * 86400000LL)
#define MAX_BOXES 64
#define MAX_ROWS 512
#define MIN_BOX_W 34
#define TIGHT_BOX_W 28
#define WIDE_BOX_W 110
#define MIN_W 30
#define MIN_H 8
#define GRAPH_MAX 4
#define MAX_COLS 4096
#define MAX_LINES 2048
#define RESP_MAX (16u << 20)

#define FG(rgb) ((uint32_t)(rgb) | 0x1000000u)
#define DIMMED 0x2000000u
#define C_TITLE 0u
#define C_TEXT 0u
#define C_DIM DIMMED
#define C_FAINT (FG(0x808080) | DIMMED)
#define C_HOT FG(0x5f9fc8)
#define C_ERR FG(0xc76060)
#define G_LO 0x5f9f62u
#define G_MID 0xb59a3cu
#define G_HI 0xc76060u
#define A_BOLD 1
#define A_DIM 2

static const char ATOP_USAGE[] =
    "usage: atop [--json] [--once] [--socket PATH] [--direct] [--now-ms MS]\n"
    "       auth-router quota [--json]\n";

static const char ALT_ON[] = "\033[?1049h\033[?25l\033[?7l";
static const char ALT_OFF[] = "\033[0m\033[?7h\033[?25h\033[?1049l";

static const int STEPS[] = {10, 15, 30, 60, 120, 300, 600};
static const uint32_t HUES[] = {0x6f8fbf, 0x78a074, 0xa784a0, 0x5fa39b, 0xa8925f, 0x8a8fb8};
static const char *const SUPER[] = {"\xc2\xb9", "\xc2\xb2", "\xc2\xb3", "\xe2\x81\xb4"};

static struct termios g_tio;
static volatile sig_atomic_t g_tio_saved;
static volatile sig_atomic_t g_alt;
static struct termios g_raw;
static volatile sig_atomic_t g_raw_set;
static volatile sig_atomic_t g_resumed;
static volatile sig_atomic_t g_winch;
static volatile sig_atomic_t g_child_pid;
static int64_t g_now_fixed;

typedef struct {
    char prov[48];
    char acct[48];
    char win[48];
    char used[8];
    char resets[48];
    char note[512];
    int64_t pct;
    bool has_pct;
    bool err;
} line_t;

enum { R_WIN, R_BAL, R_SUM, R_TEXT };

typedef struct {
    int kind;
    char label[64];
    char value[24];
    char right[40];
    char text[200];
    double frac;
    int64_t pct;
    bool has_pct;
    bool err;
    int series;
} row_t;

typedef struct {
    char title[112];
    char info[112];
    int panel;
    uint32_t hue;
    bool err;
    bool collapsible;
    int r0;
    int rn;
    int vis;
    int x;
    int y;
    int w;
    int h;
    bool shown;
} box_t;

typedef struct {
    char id[96];
    char label[64];
    int64_t last;
    int n;
    int32_t v[HIST_CAP];
} series_t;

typedef struct {
    uint32_t cp;
    uint32_t fg;
    uint8_t at;
} cell_t;

static series_t g_hist[HIST_MAX];
static size_t g_nhist;
static row_t g_rows[MAX_ROWS];
static int g_nrows;
static box_t g_boxes[MAX_BOXES];
static int g_nboxes;
static char g_pnames[4][48];
static int g_npanels;
static cell_t *g_back;
static cell_t *g_front;
static int g_w;
static int g_h;
static bool g_full;
static bool g_color;
static bool g_truecolor;

static int64_t clock_ms(void) {
    return g_now_fixed > 0 ? g_now_fixed : now_ms();
}

static void term_restore(void) {
    if (g_tio_saved) tcsetattr(STDIN_FILENO, TCSANOW, &g_tio);
    if (g_alt && write(STDOUT_FILENO, ALT_OFF, sizeof(ALT_OFF) - 1) < 0) {
        g_alt = 0;
    }
    g_alt = 0;
}

static void on_sig(int sig) {
    if (g_child_pid > 0) kill((pid_t)g_child_pid, SIGTERM);
    term_restore();
    signal(sig, SIG_DFL);
    raise(sig);
}

static void on_winch(int sig) {
    (void)sig;
    g_winch = 1;
}

static void on_tstp(int sig) {
    (void)sig;
    int saved = errno;
    bool alt = g_alt;
    term_restore();
    signal(SIGTSTP, SIG_DFL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGTSTP);
    sigprocmask(SIG_UNBLOCK, &m, NULL);
    raise(SIGTSTP);
    if (g_raw_set) tcsetattr(STDIN_FILENO, TCSANOW, &g_raw);
    if (alt && write(STDOUT_FILENO, ALT_ON, sizeof(ALT_ON) - 1) > 0) g_alt = 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_tstp;
    sigaction(SIGTSTP, &sa, NULL);
    g_resumed = 1;
    errno = saved;
}

static void clean_copy(char *out, size_t n, const char *s) {
    size_t i = 0;
    for (; s && s[i] && i + 1 < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        out[i] = (ch < 0x20 || ch == 0x7f) ? '?' : (char)ch;
    }
    out[i] = '\0';
}

static void fmt_left(int64_t ms, char *out, size_t n) {
    if (ms <= 0) {
        snprintf(out, n, "now");
        return;
    }
    long long m = (long long)((ms + 59999) / 60000);
    if (m < 60) snprintf(out, n, "%lldm", m);
    else if (m < 1440) snprintf(out, n, "%lldh%02lldm", m / 60, m % 60);
    else snprintf(out, n, "%lldd%lldh", m / 1440, (m % 1440) / 60);
}

static void fmt_age(int64_t ms, char *out, size_t n) {
    long long m = (long long)(ms / 60000);
    if (m < 60) snprintf(out, n, "%lldm old", m);
    else snprintf(out, n, "%lldh%02lldm old", m / 60, m % 60);
}

static jval_t *fetch(const char *sock_path, bool force_direct, char *err, size_t err_n) {
    jval_t *req = j_obj();
    j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
    j_obj_set(req, "op", j_str("quota"));
    jval_t *resp = NULL;
    if (!force_direct) {
        daemon_rpc_status_t st = daemon_rpc(sock_path, req, ATOP_RPC_MS, &resp, err, err_n);
        if (st == DAEMON_RPC_OK) {
            j_free(req);
            return resp;
        }
        if (st == DAEMON_RPC_ERR) {
            j_free(req);
            return NULL;
        }
    }
    resp = router_exec_direct(req, false);
    j_free(req);
    if (!resp) snprintf(err, err_n, "direct quota collection failed");
    return resp;
}

static size_t build_lines(const jval_t *resp, line_t *lines, size_t max, int64_t now) {
    size_t n = 0;
    const jval_t *accs = j_obj_get(resp, "accounts");
    for (size_t i = 0; accs && accs->type == J_ARR && i < accs->arr_len && n < max; i++) {
        const jval_t *a = accs->arr[i];
        const char *status = j_str_at(a, "status");
        char head[256];
        head[0] = '\0';
        const char *plan = j_str_at(a, "plan");
        int64_t fetched = 0;
        j_int_at(a, "fetched_ms", &fetched);
        char age[32];
        age[0] = '\0';
        if (fetched > 0 && now - fetched >= 90000) fmt_age(now - fetched, age, sizeof(age));
        char rnote[128];
        clean_copy(rnote, sizeof(rnote), j_str_at(a, "note"));
        char pl[48];
        clean_copy(pl, sizeof(pl), plan);
        snprintf(head, sizeof(head), "%s%s%s%s%s", pl, (pl[0] && rnote[0]) ? " · " : "", rnote,
                 ((pl[0] || rnote[0]) && age[0]) ? " · " : "", age);
        size_t first = n;
        line_t *l = &lines[n];
        memset(l, 0, sizeof(*l));
        if (strcmp(status, "ok") != 0) {
            snprintf(l->win, sizeof(l->win), "%s", strcmp(status, "unsupported") == 0 ? "-" : "error");
            char msg[200];
            clean_copy(msg, sizeof(msg), j_str_at(a, "error"));
            snprintf(l->note, sizeof(l->note), "%s%s%s", msg, age[0] ? " · " : "", age);
            l->err = strcmp(status, "error") == 0;
            n++;
        } else {
            const jval_t *wins = j_obj_get(a, "windows");
            const char *bal = j_str_at(a, "balance");
            const char *tu = j_str_at(a, "total_used");
            if (bal[0] || tu[0]) {
                snprintf(l->win, sizeof(l->win), "credits");
                char b[64], u[64];
                clean_copy(b, sizeof(b), bal[0] ? bal : "?");
                clean_copy(u, sizeof(u), tu[0] ? tu : "?");
                snprintf(l->note, sizeof(l->note), "balance $%s · used $%s%s%s", b, u, head[0] ? " · " : "", head);
                n++;
            }
            for (size_t w = 0; wins && wins->type == J_ARR && w < wins->arr_len && n < max; w++) {
                const jval_t *wv = wins->arr[w];
                l = &lines[n];
                memset(l, 0, sizeof(*l));
                clean_copy(l->win, sizeof(l->win), j_str_at(wv, "label"));
                int64_t used = 0;
                if (j_int_at(wv, "used", &used)) {
                    l->pct = used;
                    l->has_pct = true;
                    snprintf(l->used, sizeof(l->used), "%lld%%", (long long)used);
                } else {
                    snprintf(l->used, sizeof(l->used), "?");
                }
                int64_t rs = 0;
                if (j_int_at(wv, "resets_ms", &rs) && rs > 0) fmt_left(rs - now, l->resets, sizeof(l->resets));
                if (n == first) snprintf(l->note, sizeof(l->note), "%s", head);
                n++;
            }
            if (n == first) {
                l = &lines[n];
                memset(l, 0, sizeof(*l));
                snprintf(l->win, sizeof(l->win), "-");
                snprintf(l->note, sizeof(l->note), "no windows reported%s%s", head[0] ? " · " : "", head);
                n++;
            }
        }
        if (n > first) {
            clean_copy(lines[first].prov, sizeof(lines[first].prov), j_str_at(a, "provider"));
            clean_copy(lines[first].acct, sizeof(lines[first].acct), j_str_at(a, "name"));
        }
    }
    return n;
}

static void pad(sb_t *out, const char *s, size_t w) {
    sb_puts(out, s);
    for (size_t i = strlen(s); i < w; i++) sb_putc(out, ' ');
}

static void render_table(const jval_t *resp, sb_t *out) {
    static line_t lines[ATOP_LINES];
    size_t n = build_lines(resp, lines, ATOP_LINES, clock_ms());
    size_t wp = strlen("PROVIDER"), wa = strlen("ACCOUNT"), ww = strlen("WINDOW"), wr = strlen("RESETS");
    for (size_t i = 0; i < n; i++) {
        if (strlen(lines[i].prov) > wp) wp = strlen(lines[i].prov);
        if (strlen(lines[i].acct) > wa) wa = strlen(lines[i].acct);
        if (strlen(lines[i].win) > ww) ww = strlen(lines[i].win);
        if (strlen(lines[i].resets) > wr) wr = strlen(lines[i].resets);
    }
    pad(out, "PROVIDER", wp + 2);
    pad(out, "ACCOUNT", wa + 2);
    pad(out, "WINDOW", ww + 2);
    sb_puts(out, " USED  ");
    pad(out, "", ATOP_BAR + 2);
    pad(out, "RESETS", wr + 2);
    sb_puts(out, "NOTE");
    sb_putc(out, '\n');
    for (size_t i = 0; i < n; i++) {
        const line_t *l = &lines[i];
        if (i > 0 && l->prov[0]) sb_putc(out, '\n');
        pad(out, l->prov, wp + 2);
        pad(out, l->acct, wa + 2);
        pad(out, l->win, ww + 2);
        char used[16];
        snprintf(used, sizeof(used), "%5s", l->used);
        sb_puts(out, used);
        sb_puts(out, "  ");
        if (l->has_pct) {
            int64_t fill = (l->pct * ATOP_BAR + 50) / 100;
            if (fill < 0) fill = 0;
            if (fill > ATOP_BAR) fill = ATOP_BAR;
            for (int64_t k = 0; k < ATOP_BAR; k++) sb_putc(out, k < fill ? '#' : '-');
        } else {
            pad(out, "", ATOP_BAR);
        }
        sb_puts(out, "  ");
        pad(out, l->resets, wr + 2);
        sb_puts(out, l->note);
        size_t len = out->len;
        while (len > 0 && out->data[len - 1] == ' ') len--;
        out->len = len;
        out->data[len] = '\0';
        sb_putc(out, '\n');
    }
}

static void emit_all(int fd, const char *data, size_t len) {
    size_t off = 0;
    while (data && off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static int once(const char *sock_path, bool force_direct, bool json) {
    char err[256];
    err[0] = '\0';
    jval_t *resp = fetch(sock_path, force_direct, err, sizeof(err));
    if (!resp) {
        fprintf(stderr, "atop: %s\n", err[0] ? err : "quota request failed");
        return 1;
    }
    const jval_t *ok = j_obj_get(resp, "ok");
    bool good = ok && ok->type == J_BOOL && ok->b;
    if (json) {
        char *s = j_show(resp);
        if (s) printf("%s\n", s);
        free(s);
    } else if (good) {
        sb_t sb;
        sb_init(&sb);
        render_table(resp, &sb);
        fflush(stdout);
        emit_all(STDOUT_FILENO, sb.data, sb.len);
        sb_free(&sb);
    } else {
        fprintf(stderr, "atop: %s\n", j_str_at(resp, "error")[0] ? j_str_at(resp, "error") : "quota request failed");
    }
    j_free(resp);
    return good ? 0 : 1;
}

static bool hist_path(char *out, size_t n) {
    const char *x = getenv("XDG_STATE_HOME");
    int r = -1;
    if (x && x[0] == '/') r = snprintf(out, n, "%s/atop/history", x);
    else if (getenv("HOME") && getenv("HOME")[0] == '/') r = snprintf(out, n, "%s/.local/state/atop/history", getenv("HOME"));
    return r > 0 && (size_t)r < n;
}

static int hist_find(const char *id, const char *label) {
    for (size_t i = 0; i < g_nhist; i++) {
        if (strcmp(g_hist[i].id, id) == 0 && strcmp(g_hist[i].label, label) == 0) return (int)i;
    }
    return -1;
}

static void hist_load(const char *path, int64_t now) {
    g_nhist = 0;
    char *data = NULL;
    size_t len = 0;
    if (!file_read(path, &data, &len, NULL) || !data) return;
    char *save = NULL;
    char *line = strtok_r(data, "\n", &save);
    if (!line || strcmp(line, "atop-history 1") != 0) {
        free(data);
        return;
    }
    while ((line = strtok_r(NULL, "\n", &save)) && g_nhist < HIST_MAX) {
        char *f[4];
        int nf = 0;
        char *p = line;
        f[nf++] = p;
        while (*p && nf < 4) {
            if (*p == '\t') {
                *p = '\0';
                f[nf++] = p + 1;
            }
            p++;
        }
        if (nf != 4 || !f[0][0] || strlen(f[0]) >= sizeof(g_hist[0].id) || strlen(f[1]) >= sizeof(g_hist[0].label)) continue;
        int64_t last = 0;
        if (!str_to_i64(f[2], &last) || last <= 0 || now - last > HIST_TTL_MS) continue;
        if (hist_find(f[0], f[1]) >= 0) continue;
        series_t *s = &g_hist[g_nhist];
        memset(s, 0, sizeof(*s));
        snprintf(s->id, sizeof(s->id), "%s", f[0]);
        snprintf(s->label, sizeof(s->label), "%s", f[1]);
        s->last = last;
        char *vsave = NULL;
        for (char *v = strtok_r(f[3], ",", &vsave); v; v = strtok_r(NULL, ",", &vsave)) {
            int64_t x = 0;
            if (!str_to_i64(v, &x) || x < 0 || x > 2000000000) continue;
            if (s->n == HIST_CAP) {
                memmove(s->v, s->v + 1, sizeof(s->v[0]) * (HIST_CAP - 1));
                s->n--;
            }
            s->v[s->n++] = (int32_t)x;
        }
        g_nhist++;
    }
    free(data);
}

static bool hist_push(const char *id, const char *label, int64_t at, double val) {
    if (at <= 0 || !(val >= 0) || val > 2000000000.0) return false;
    int i = hist_find(id, label);
    if (i < 0) {
        if (g_nhist == HIST_MAX) {
            size_t old = 0;
            for (size_t k = 1; k < g_nhist; k++) {
                if (g_hist[k].last < g_hist[old].last) old = k;
            }
            g_hist[old] = g_hist[--g_nhist];
        }
        i = (int)g_nhist++;
        memset(&g_hist[i], 0, sizeof(g_hist[i]));
        snprintf(g_hist[i].id, sizeof(g_hist[i].id), "%s", id);
        snprintf(g_hist[i].label, sizeof(g_hist[i].label), "%s", label);
    }
    series_t *s = &g_hist[i];
    if (at <= s->last) return false;
    if (s->n == HIST_CAP) {
        memmove(s->v, s->v + 1, sizeof(s->v[0]) * (HIST_CAP - 1));
        s->n--;
    }
    s->v[s->n++] = (int32_t)(val + 0.5);
    s->last = at;
    return true;
}

static bool parse_num(const char *s, double *out) {
    if (!s || !s[0]) return false;
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s || *end || !(v >= 0) || v > 1e12) return false;
    *out = v;
    return true;
}

static bool parse_money_note(const char *note, char *cur, size_t cur_n, char *unit, size_t unit_n, double *used, double *limit) {
    const char *p = note;
    size_t ci = 0;
    cur[0] = unit[0] = '\0';
    while ((*p >= 'A' && *p <= 'Z') && ci < 4) cur[ci++ % cur_n] = *p++;
    if (ci > 0) {
        if (ci < 2 || *p != ' ' || ci >= cur_n) return false;
        cur[ci] = '\0';
        p++;
    }
    char *end = NULL;
    double u = strtod(p, &end);
    if (end == p || *end != '/') return false;
    p = end + 1;
    double l = strtod(p, &end);
    if (end == p) return false;
    p = end;
    if (*p == ' ') {
        p++;
        size_t ui = 0;
        while (*p >= 'a' && *p <= 'z' && ui + 1 < unit_n) unit[ui++] = *p++;
        unit[ui] = '\0';
        if (!ui) return false;
    }
    if (*p || !(u >= 0) || !(l > 0) || u > 1e12 || l > 1e12) return false;
    *used = u;
    *limit = l;
    return true;
}

static void hist_record(const jval_t *resp, int64_t now) {
    char path[1024];
    if (!hist_path(path, sizeof(path))) return;
    char lockp[1100];
    snprintf(lockp, sizeof(lockp), "%s.lock", path);
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    int lfd = -1;
    if (ensure_dir(dir, 0700)) {
        lfd = open(lockp, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lfd >= 0 && flock(lfd, LOCK_EX | LOCK_NB) != 0) {
            close(lfd);
            lfd = -1;
        }
    }
    hist_load(path, now);
    bool changed = false;
    const jval_t *accs = j_obj_get(resp, "accounts");
    for (size_t i = 0; accs && accs->type == J_ARR && i < accs->arr_len; i++) {
        const jval_t *a = accs->arr[i];
        int64_t at = 0;
        if (strcmp(j_str_at(a, "status"), "ok") != 0 || !j_int_at(a, "fetched_ms", &at)) continue;
        char id[96];
        clean_copy(id, sizeof(id), j_str_at(a, "id"));
        if (!id[0]) continue;
        const jval_t *wins = j_obj_get(a, "windows");
        for (size_t w = 0; wins && wins->type == J_ARR && w < wins->arr_len; w++) {
            int64_t used = 0;
            char label[64];
            clean_copy(label, sizeof(label), j_str_at(wins->arr[w], "label"));
            if (label[0] && j_int_at(wins->arr[w], "used", &used)) changed |= hist_push(id, label, at, (double)used);
        }
        double bal = 0, u = 0, l = 0;
        if (parse_num(j_str_at(a, "balance"), &bal)) changed |= hist_push(id, "$balance", at, bal * 100.0);
        char cur[8], unit[16];
        if (parse_money_note(j_str_at(a, "note"), cur, sizeof(cur), unit, sizeof(unit), &u, &l)) {
            changed |= hist_push(id, "$left", at, (l > u ? l - u : 0) * 100.0);
        }
    }
    if (changed && lfd >= 0) {
        sb_t sb;
        sb_init(&sb);
        sb_puts(&sb, "atop-history 1\n");
        for (size_t i = 0; i < g_nhist; i++) {
            const series_t *s = &g_hist[i];
            sb_printf(&sb, "%s\t%s\t%lld\t", s->id, s->label, (long long)s->last);
            for (int k = 0; k < s->n; k++) sb_printf(&sb, k ? ",%d" : "%d", (int)s->v[k]);
            sb_putc(&sb, '\n');
        }
        file_write_0600(path, sb.data, sb.len);
        sb_free(&sb);
    }
    if (lfd >= 0) {
        flock(lfd, LOCK_UN);
        close(lfd);
    }
}

static uint32_t fnv(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

static void fmt_amount(double v, const char *cur, const char *unit, char *out, size_t n) {
    char num[32];
    if (v >= 999950.0) snprintf(num, sizeof(num), "%.1fM", v / 1e6);
    else if (v >= 9999.5) snprintf(num, sizeof(num), "%.1fk", v / 1e3);
    else if (v >= 1000.0) {
        long long iv = (long long)(v + 0.5);
        snprintf(num, sizeof(num), "%lld,%03lld", iv / 1000, iv % 1000);
    } else if (unit[0]) snprintf(num, sizeof(num), "%.0f", v);
    else snprintf(num, sizeof(num), "%.2f", v);
    size_t nl = strlen(num);
    if (nl > 3 && (num[nl - 1] == 'k' || num[nl - 1] == 'M') && num[nl - 3] == '.' && num[nl - 2] == '0') {
        num[nl - 3] = num[nl - 1];
        num[nl - 2] = '\0';
    }
    const char *u = strcmp(unit, "credits") == 0 ? "cr" : unit;
    if (!cur[0] || strcmp(cur, "USD") == 0) snprintf(out, n, "%s%s%s%s", cur[0] || !unit[0] ? "$" : "", num, u[0] ? " " : "", u);
    else snprintf(out, n, "%s %s%s%s", cur, num, u[0] ? " " : "", u);
}

static row_t *row_new(int kind) {
    if (g_nrows >= MAX_ROWS) return NULL;
    row_t *r = &g_rows[g_nrows++];
    memset(r, 0, sizeof(*r));
    r->kind = kind;
    r->series = -1;
    return r;
}

static int panel_of(const char *prov) {
    for (int i = 0; i < g_npanels; i++) {
        if (strcmp(g_pnames[i], prov) == 0) return i;
    }
    if (g_npanels < 4) {
        snprintf(g_pnames[g_npanels], sizeof(g_pnames[0]), "%s", prov);
        return g_npanels++;
    }
    return 3;
}

static void join(char *out, size_t n, const char *a) {
    if (!a[0]) return;
    size_t l = strlen(out);
    snprintf(out + l, n - l, "%s%s", l ? " · " : "", a);
}

static size_t label_lcp(const jval_t *wins, size_t first, bool (*pick)(const jval_t *)) {
    const char *ref = NULL;
    size_t lcp = 0;
    for (size_t w = first; w < wins->arr_len; w++) {
        if (!pick(wins->arr[w])) continue;
        const char *l = j_str_at(wins->arr[w], "label");
        if (!ref) {
            ref = l;
            lcp = strlen(l);
            continue;
        }
        size_t k = 0;
        while (k < lcp && l[k] && l[k] == ref[k]) k++;
        lcp = k;
    }
    while (lcp > 0 && ref[lcp - 1] != '-' && ref[lcp - 1] != '.' && ref[lcp - 1] != '/') lcp--;
    for (size_t w = first; ref && lcp && w < wins->arr_len; w++) {
        if (pick(wins->arr[w]) && strlen(j_str_at(wins->arr[w], "label")) <= lcp) return 0;
    }
    return lcp;
}

static bool exhausted(const jval_t *w) {
    int64_t u = 0;
    return j_int_at(w, "used", &u) && u >= 100;
}

static void build_model(const jval_t *resp, int64_t now, bool expanded) {
    g_nrows = 0;
    g_nboxes = 0;
    g_npanels = 0;
    const jval_t *accs = j_obj_get(resp, "accounts");
    for (size_t i = 0; accs && accs->type == J_ARR && i < accs->arr_len && g_nboxes < MAX_BOXES; i++) {
        const jval_t *a = accs->arr[i];
        box_t *b = &g_boxes[g_nboxes];
        memset(b, 0, sizeof(*b));
        char prov[48], name[48], id[96];
        clean_copy(prov, sizeof(prov), j_str_at(a, "provider"));
        clean_copy(name, sizeof(name), j_str_at(a, "name"));
        clean_copy(id, sizeof(id), j_str_at(a, "id"));
        if (!name[0] || strcmp(prov, name) == 0) snprintf(b->title, sizeof(b->title), "%s", prov[0] ? prov : name);
        else snprintf(b->title, sizeof(b->title), "%s · %s", prov, name);
        b->panel = panel_of(prov);
        b->hue = FG(HUES[fnv(prov) % (sizeof(HUES) / sizeof(HUES[0]))]);
        b->r0 = g_nrows;
        const char *status = j_str_at(a, "status");
        int64_t fetched = 0;
        char age[32] = "";
        if (j_int_at(a, "fetched_ms", &fetched) && fetched > 0 && now - fetched >= 90000) fmt_age(now - fetched, age, sizeof(age));
        char tmp[200];
        if (strcmp(status, "ok") != 0) {
            row_t *r = row_new(R_TEXT);
            b->err = strcmp(status, "error") == 0;
            clean_copy(tmp, sizeof(tmp), j_str_at(a, "error"));
            if (r) {
                snprintf(r->text, sizeof(r->text), "%s", tmp[0] ? tmp : (b->err ? "quota request failed" : "quota not reported"));
                r->err = b->err;
            }
            if (b->err) join(b->info, sizeof(b->info), "error");
            join(b->info, sizeof(b->info), age);
            b->rn = g_nrows - b->r0;
            g_nboxes++;
            continue;
        }
        char cur[8], unit[16], note[128];
        double used = 0, limit = 0;
        clean_copy(note, sizeof(note), j_str_at(a, "note"));
        bool money = parse_money_note(note, cur, sizeof(cur), unit, sizeof(unit), &used, &limit);
        clean_copy(tmp, sizeof(tmp), j_str_at(a, "plan"));
        join(b->info, sizeof(b->info), tmp);
        if (!money) join(b->info, sizeof(b->info), note);
        join(b->info, sizeof(b->info), age);
        const jval_t *wins = j_obj_get(a, "windows");
        size_t nw = wins && wins->type == J_ARR ? wins->arr_len : 0;
        size_t nex = 0;
        for (size_t w = 0; w < nw; w++) nex += exhausted(wins->arr[w]);
        bool collapse = nw > 4 && nex >= 2;
        b->collapsible = collapse;
        if (collapse && expanded) collapse = false;
        int64_t ex_reset = 0;
        for (size_t w = 0; w < nw; w++) {
            const jval_t *wv = wins->arr[w];
            int64_t rs = 0;
            bool has_rs = j_int_at(wv, "resets_ms", &rs) && rs > 0;
            if (collapse && exhausted(wv)) {
                if (has_rs && (!ex_reset || rs < ex_reset)) ex_reset = rs;
                continue;
            }
            row_t *r = row_new(R_WIN);
            if (!r) break;
            clean_copy(r->label, sizeof(r->label), j_str_at(wv, "label"));
            int64_t u = 0;
            if (j_int_at(wv, "used", &u)) {
                r->has_pct = true;
                r->pct = u;
                r->frac = u <= 0 ? 0.0 : u >= 100 ? 1.0 : (double)u / 100.0;
                snprintf(r->value, sizeof(r->value), "%lld%%", (long long)u);
            } else {
                snprintf(r->value, sizeof(r->value), "?");
            }
            if (has_rs) fmt_left(rs - now, r->right, sizeof(r->right));
            r->series = hist_find(id, r->label);
        }
        if (collapse) {
            row_t *r = row_new(R_SUM);
            if (r) {
                snprintf(r->label, sizeof(r->label), "%zu exhausted", nex);
                r->pct = 100;
                r->has_pct = true;
                size_t lcp = label_lcp(wins, 0, exhausted);
                size_t tl = 0;
                for (size_t w = 0; w < nw; w++) {
                    if (!exhausted(wins->arr[w])) continue;
                    char l[64];
                    clean_copy(l, sizeof(l), j_str_at(wins->arr[w], "label") + lcp);
                    int k = snprintf(r->text + tl, sizeof(r->text) - tl, "%s%s", tl ? " " : "", l);
                    if (k < 0 || (size_t)k >= sizeof(r->text) - tl) break;
                    tl += (size_t)k;
                }
                if (ex_reset) fmt_left(ex_reset - now, r->right, sizeof(r->right));
            }
        }
        double bal = 0, tu = 0;
        bool has_bal = parse_num(j_str_at(a, "balance"), &bal);
        bool has_tu = parse_num(j_str_at(a, "total_used"), &tu);
        if (has_bal || has_tu) {
            row_t *r = row_new(R_BAL);
            if (r) {
                snprintf(r->label, sizeof(r->label), "balance");
                if (has_bal) fmt_amount(bal, "", "", r->value, sizeof(r->value));
                else snprintf(r->value, sizeof(r->value), "?");
                if (has_tu) {
                    char t[24];
                    fmt_amount(tu, "", "", t, sizeof(t));
                    snprintf(r->right, sizeof(r->right), "%s used", t);
                }
                r->frac = has_bal && has_tu && bal + tu > 0 ? bal / (bal + tu) : has_bal ? 1.0 : 0.0;
                r->series = hist_find(id, "$balance");
            }
        }
        if (money) {
            row_t *r = row_new(R_BAL);
            if (r) {
                double left = limit > used ? limit - used : 0;
                snprintf(r->label, sizeof(r->label), "left");
                fmt_amount(left, cur, unit, r->value, sizeof(r->value));
                char t[24];
                fmt_amount(limit, cur, unit, t, sizeof(t));
                snprintf(r->right, sizeof(r->right), "of %s", t);
                r->frac = left / limit;
                r->series = hist_find(id, "$left");
            }
        }
        if (g_nrows == b->r0) {
            row_t *r = row_new(R_TEXT);
            if (r) snprintf(r->text, sizeof(r->text), "no windows reported");
        }
        b->rn = g_nrows - b->r0;
        g_nboxes++;
    }
}

static uint32_t lerp_rgb(uint32_t a, uint32_t b, double t) {
    uint32_t out = 0;
    for (int s = 16; s >= 0; s -= 8) {
        double ca = (double)((a >> s) & 255), cb = (double)((b >> s) & 255);
        out |= (uint32_t)(ca + (cb - ca) * t + 0.5) << s;
    }
    return out;
}

static uint32_t grad(double t) {
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    return FG(t < 0.6 ? lerp_rgb(G_LO, G_MID, t / 0.6) : lerp_rgb(G_MID, G_HI, (t - 0.6) / 0.4));
}

static void grid_resize(int w, int h) {
    free(g_back);
    free(g_front);
    g_back = calloc((size_t)w * (size_t)h, sizeof(cell_t));
    g_front = calloc((size_t)w * (size_t)h, sizeof(cell_t));
    if (!g_back || !g_front) {
        if (g_child_pid > 0) kill((pid_t)g_child_pid, SIGTERM);
        term_restore();
        fputs("atop: out of memory\n", stderr);
        exit(1);
    }
    g_w = w;
    g_h = h;
    g_full = true;
}

static void grid_clear(void) {
    for (int i = 0; i < g_w * g_h; i++) {
        g_back[i].cp = ' ';
        g_back[i].fg = 0;
        g_back[i].at = 0;
    }
}

static void put_cp(int x, int y, uint32_t cp, uint32_t fg, uint8_t at) {
    if (x < 0 || y < 0 || x >= g_w || y >= g_h) return;
    cell_t *c = &g_back[y * g_w + x];
    c->cp = cp;
    c->fg = fg;
    c->at = at;
}

static uint32_t utf8_next(const char **ps) {
    const unsigned char *s = (const unsigned char *)*ps;
    uint32_t c0 = s[0];
    int len = c0 >= 0xc2 && c0 <= 0xdf ? 2 : c0 >= 0xe0 && c0 <= 0xef ? 3 : c0 >= 0xf0 && c0 <= 0xf4 ? 4 : 1;
    uint32_t cp = len == 2 ? (c0 & 31u) : len == 3 ? (c0 & 15u) : (c0 & 7u);
    for (int i = 1; i < len; i++) {
        if ((s[i] & 0xc0) != 0x80) {
            len = 1;
            break;
        }
        cp = (cp << 6) | (s[i] & 63u);
    }
    if (len == 1) cp = c0 < 0x80 ? c0 : '?';
    else if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10ffff))) cp = '?';
    *ps += len;
    return cp;
}

static int ulen(const char *s) {
    int n = 0;
    while (*s) {
        utf8_next(&s);
        n++;
    }
    return n;
}

static uint32_t narrow_cp(uint32_t cp) {
    static const uint32_t OK[][2] = {
        {0x20, 0x7e}, {0xa0, 0xac}, {0xae, 0x2ff}, {0x370, 0x482}, {0x48a, 0x52f}, {0x2010, 0x2027},
        {0x2030, 0x205e}, {0x2070, 0x209c}, {0x20a0, 0x20c0}, {0x2190, 0x21ff}, {0x2500, 0x25fc}, {0x2800, 0x28ff},
    };
    for (size_t i = 0; i < sizeof(OK) / sizeof(OK[0]); i++) {
        if (cp >= OK[i][0] && cp <= OK[i][1]) return cp;
    }
    return '?';
}

static int put_str(int x, int y, const char *s, int maxw, uint32_t fg, uint8_t at) {
    if (maxw <= 0) return 0;
    int len = ulen(s);
    int lim = len > maxw ? maxw - 1 : len;
    int i = 0;
    while (*s && i < lim) put_cp(x + i++, y, narrow_cp(utf8_next(&s)), fg, at);
    if (len > maxw) put_cp(x + i++, y, 0x2026, fg, at);
    return i;
}

static void put_rpad(int x, int y, const char *s, int w, uint32_t fg, uint8_t at) {
    int len = ulen(s);
    if (len > w) len = w;
    put_str(x + w - len, y, s, w, fg, at);
}

static void hline(int x, int y, int n, uint32_t cp, uint32_t fg) {
    for (int i = 0; i < n; i++) put_cp(x + i, y, cp, fg, 0);
}

static int level_of(int32_t v, int32_t max, int top) {
    if (max <= 0) return 1;
    if (v > max) v = max;
    return 1 + (int)(((int64_t)v * (top - 1) + max / 2) / max);
}

static int clampi(int v, int lo, int hi) {
    return v < lo ? lo : v > hi ? hi : v;
}

static void draw_spark(int x, int y, int w, int g, const series_t *s, bool pct, uint32_t hue) {
    static const uint8_t L[5] = {0, 0x40, 0x44, 0x46, 0x47};
    static const uint8_t R[5] = {0, 0x80, 0xa0, 0xb0, 0xb8};
    if (!s || w <= 0 || g <= 0) return;
    int32_t max = pct ? 100 : 0;
    int slots = w * 2;
    if (!pct) {
        for (int k = s->n - slots < 0 ? 0 : s->n - slots; k < s->n; k++) {
            if (s->v[k] > max) max = s->v[k];
        }
    }
    int top = 4 * g;
    for (int c = 0; c < w; c++) {
        int ia = s->n - slots + c * 2, ib = ia + 1;
        int la = ia >= 0 ? level_of(s->v[ia], max, top) : 0;
        int lb = ib >= 0 ? level_of(s->v[ib], max, top) : 0;
        if (!la && !lb) continue;
        int32_t hi = ib >= 0 ? s->v[ib] : 0;
        if (ia >= 0 && s->v[ia] > hi) hi = s->v[ia];
        for (int r = 0; r < g; r++) {
            int base = 4 * (g - 1 - r);
            int da = clampi(la - base, 0, 4), db = clampi(lb - base, 0, 4);
            if (!da && !db) continue;
            uint32_t fg = !pct ? hue : g == 1 ? grad((double)hi / 100.0) : grad(((double)(g - r) - 0.5) / g);
            put_cp(x + c, y + r, 0x2800u + L[da] + R[db], fg, 0);
        }
    }
}

static void draw_meter(int x, int y, int w, double frac, bool pct, uint32_t hue) {
    int fill = (int)(frac * w + 0.5);
    if (frac > 0 && fill == 0) fill = 1;
    for (int i = 0; i < w; i++) {
        if (i < fill) put_cp(x + i, y, 0x25a0, pct ? grad(((double)i + 0.5) / w) : hue, 0);
        else put_cp(x + i, y, g_color ? 0x25a0 : 0xb7, C_FAINT, 0);
    }
}

static void draw_frame(int x, int y, int w, int h, uint32_t bc) {
    put_cp(x, y, 0x256d, bc, 0);
    hline(x + 1, y, w - 2, 0x2500, bc);
    put_cp(x + w - 1, y, 0x256e, bc, 0);
    for (int r = 1; r < h - 1; r++) {
        put_cp(x, y + r, 0x2502, bc, 0);
        put_cp(x + w - 1, y + r, 0x2502, bc, 0);
        hline(x + 1, y + r, w - 2, ' ', 0);
    }
    put_cp(x, y + h - 1, 0x2570, bc, 0);
    hline(x + 1, y + h - 1, w - 2, 0x2500, bc);
    put_cp(x + w - 1, y + h - 1, 0x256f, bc, 0);
}

static int tag(int x, int y, int maxw, const char *hot, const char *text, uint32_t bc, uint32_t fg) {
    int need = 2 + ulen(hot) + ulen(text);
    if (need > maxw) return 0;
    put_cp(x, y, 0x2510, bc, 0);
    int k = 1 + put_str(x + 1, y, hot, maxw, C_HOT, A_BOLD);
    k += put_str(x + k, y, text, maxw - k - 1, fg, fg == C_TITLE ? A_BOLD : 0);
    put_cp(x + k, y, 0x250c, bc, 0);
    return k + 1;
}

static int row_lines(const row_t *r, int g) {
    return r->kind == R_WIN || r->kind == R_BAL ? g : 1;
}

static int box_lines(const box_t *b, int g) {
    int n = 0;
    for (int i = 0; i < b->rn; i++) n += row_lines(&g_rows[b->r0 + i], g);
    return n;
}

static void draw_box(const box_t *b, bool expanded, int g) {
    int x0 = b->x, y0 = b->y, w = b->w, h = b->h;
    draw_frame(x0, y0, w, h, b->hue);
    const char *sup = b->panel >= 0 && b->panel < 4 ? SUPER[b->panel] : "";
    int room = w - 4;
    int tl = ulen(b->title);
    int il = b->info[0] ? ulen(b->info) + 2 : 0;
    if (il && 2 + 1 + tl + 1 + il > room) il = 0;
    int maxt = (il ? room - il - 1 : room) - 2 - ulen(sup);
    if (maxt >= 3) {
        put_cp(x0 + 2, y0, 0x2510, b->hue, 0);
        int k = 1 + put_str(x0 + 3, y0, sup, 4, C_HOT, A_BOLD);
        k += put_str(x0 + 2 + k, y0, b->title, maxt, C_TITLE, A_BOLD);
        put_cp(x0 + 2 + k, y0, 0x250c, b->hue, 0);
    }
    if (il) tag(x0 + w - 2 - il, y0, il, "", b->info, b->hue, b->err ? C_ERR : C_DIM);
    int iw = w - 4, ix = x0 + 2;
    int lw = 0, vw = 4, rw = 0;
    for (int i = 0; i < b->rn; i++) {
        const row_t *r = &g_rows[b->r0 + i];
        if (r->kind == R_TEXT) continue;
        if (ulen(r->label) > lw) lw = ulen(r->label);
        if (ulen(r->value) > vw) vw = ulen(r->value);
        if (ulen(r->right) > rw) rw = ulen(r->right);
    }
    if (vw > iw / 4 && vw > 4) vw = iw / 4 > 4 ? iw / 4 : 4;
    if (rw > iw / 3) rw = iw / 3;
    bool tall = g > 1;
    if (tall) rw = 0;
    int lcap = iw / 3 > 6 ? iw / 3 : 6;
    if (lw > lcap) lw = lcap;
    int rest = iw - lw - 1 - vw - (rw ? rw + 1 : 0) - 1;
    if (rest < 6 && rw) {
        rw = 0;
        rest = iw - lw - 1 - vw - 1;
    }
    if (rest < 6) {
        lw -= 6 - rest;
        if (lw < 3) lw = 3;
        rest = iw - lw - 1 - vw - 1;
    }
    if (rest < 1) rest = 1;
    int sw = 0, mw = rest;
    if (rest >= 12) {
        sw = clampi(rest * 2 / 5, 4, 120);
        mw = rest - sw - 1;
        if (mw > 40) {
            sw = clampi(sw + mw - 40, 4, 120);
            mw = 40;
        }
    }
    int bottom = y0 + h - 1;
    bool cut = !tall && h - 2 < b->rn;
    int shown = cut ? h - 3 : b->rn;
    int y = y0 + 1;
    for (int i = 0; i < shown; i++) {
        const row_t *r = &g_rows[b->r0 + i];
        int rl = row_lines(r, g);
        if (y + rl > bottom) break;
        if (r->kind == R_TEXT) {
            put_str(ix, y, r->text, iw, r->err ? C_ERR : C_DIM, 0);
            y++;
            continue;
        }
        bool pct = r->kind != R_BAL;
        put_str(ix, y, r->label, lw, r->kind == R_SUM ? C_DIM : C_TEXT, 0);
        int x = ix + lw + 1;
        if (r->kind == R_SUM) {
            put_str(x, y, r->text, iw - lw - 1 - (rw ? rw + 1 : 0) - (tall && r->right[0] ? ulen(r->right) + 1 : 0), C_DIM, 0);
            if (tall && r->right[0]) put_rpad(ix + iw - ulen(r->right), y, r->right, ulen(r->right), C_DIM, 0);
        } else {
            draw_meter(x, y, mw, r->frac, pct, b->hue);
            uint32_t vfg = pct && r->has_pct ? grad(r->frac) : pct ? C_DIM : C_TEXT;
            put_rpad(x + mw + 1, y, r->value, vw, vfg, r->has_pct && r->pct >= 90 ? A_BOLD : 0);
            if (sw && r->series >= 0) draw_spark(x + mw + 1 + vw + 1, y, sw, rl, &g_hist[r->series], pct, b->hue);
            if (tall && r->right[0]) {
                char t[64];
                snprintf(t, sizeof(t), "%s%s", r->kind == R_WIN ? "resets in " : "", r->right);
                put_str(x, y + 1, t, mw + 1 + vw, C_DIM, 0);
            }
        }
        if (rw) put_rpad(ix + iw - rw, y, r->right, rw, C_DIM, 0);
        y += rl;
    }
    if (cut && h >= 3) {
        char more[32];
        snprintf(more, sizeof(more), "+%d more", b->rn - shown);
        put_str(ix, y0 + h - 2, more, iw, C_DIM, 0);
    }
    if (b->collapsible) tag(x0 + 2, y0 + h - 1, w - 4, "e", expanded ? " collapse" : " expand", b->hue, C_DIM);
}

static int part_cols(const int *hs, int n, int k, int *cut) {
    static int best[MAX_BOXES + 1][MAX_BOXES + 1];
    static int from[MAX_BOXES + 1][MAX_BOXES + 1];
    int pre[MAX_BOXES + 1];
    pre[0] = 0;
    for (int i = 0; i < n; i++) pre[i + 1] = pre[i] + hs[i];
    for (int i = 0; i <= n; i++) best[1][i] = pre[i];
    for (int j = 2; j <= k; j++) {
        for (int i = 0; i <= n; i++) {
            best[j][i] = best[j - 1][i];
            from[j][i] = i;
            for (int p = 0; p < i; p++) {
                int c = best[j - 1][p] > pre[i] - pre[p] ? best[j - 1][p] : pre[i] - pre[p];
                if (c < best[j][i]) {
                    best[j][i] = c;
                    from[j][i] = p;
                }
            }
        }
    }
    cut[k] = n;
    for (int j = k, i = n; j >= 1; j--) {
        int p = j == 1 ? 0 : from[j][i];
        cut[j - 1] = p;
        i = p;
    }
    return best[k][n];
}

static int layout(int W, int H, unsigned hidden, int *g_out) {
    int idx[MAX_BOXES], hs[MAX_BOXES], n = 0;
    *g_out = 1;
    for (int i = 0; i < g_nboxes; i++) {
        g_boxes[i].shown = false;
        if (hidden & (1u << g_boxes[i].panel)) continue;
        g_boxes[i].vis = g_boxes[i].rn;
        idx[n] = i;
        hs[n++] = g_boxes[i].rn + 2;
    }
    if (!n) return 0;
    int AH = H - 1;
    int maxk = clampi(W / MIN_BOX_W, 1, n);
    int k = clampi((W + WIDE_BOX_W - 1) / WIDE_BOX_W, 1, maxk);
    int cut[MAX_BOXES + 1];
    while (part_cols(hs, n, k, cut) > AH && k < maxk) k++;
    int tightk = clampi(W / TIGHT_BOX_W, 1, n);
    while (part_cols(hs, n, k, cut) > AH && k < tightk) k++;
    int g = 1;
    for (int t = GRAPH_MAX; t >= 2; t--) {
        int ht[MAX_BOXES];
        for (int j = 0; j < n; j++) ht[j] = box_lines(&g_boxes[idx[j]], t) + 2;
        if (part_cols(ht, n, k, cut) <= AH) {
            g = t;
            memcpy(hs, ht, sizeof(ht[0]) * (size_t)n);
            break;
        }
    }
    part_cols(hs, n, k, cut);
    *g_out = g;
    int off = 0;
    for (int c = 0; c < k; c++) {
        int cw = W / k + (c < W % k ? 1 : 0);
        int total = 0;
        for (int j = cut[c]; j < cut[c + 1]; j++) total += hs[j];
        while (g == 1 && total > AH) {
            int big = -1;
            for (int j = cut[c]; j < cut[c + 1]; j++) {
                box_t *b = &g_boxes[idx[j]];
                if (b->vis > 2 && (big < 0 || b->vis > g_boxes[idx[big]].vis)) big = j;
            }
            if (big < 0) break;
            g_boxes[idx[big]].vis--;
            hs[big]--;
            total--;
        }
        int y = 1;
        for (int j = cut[c]; j < cut[c + 1]; j++) {
            box_t *b = &g_boxes[idx[j]];
            b->x = off;
            b->w = cw;
            b->y = y;
            b->h = hs[j];
            b->shown = y + b->h <= H;
            if (b->shown) y += b->h;
        }
        off += cw;
    }
    int dropped = 0;
    for (int j = 0; j < n; j++) dropped += !g_boxes[idx[j]].shown;
    return dropped;
}

typedef struct {
    const char *sock;
    bool direct;
    jval_t *resp;
    char err[256];
    pid_t child;
    int cfd;
    sb_t cbuf;
    int64_t next_fetch;
    int64_t last_done;
    int step;
    unsigned hidden;
    bool expanded;
    bool help;
} ui_t;

static void draw_center(int y, const char *s, uint32_t fg) {
    int l = ulen(s);
    put_str(l < g_w ? (g_w - l) / 2 : 0, y, s, g_w, fg, 0);
}

static int hot_word(int x, int y, const char *hot, const char *rest) {
    int k = put_str(x, y, hot, 8, C_HOT, A_BOLD);
    return k + put_str(x + k, y, rest, 40, C_DIM, 0);
}

static void draw_header(const ui_t *u, int dropped) {
    time_t t = (time_t)(clock_ms() / 1000);
    struct tm tmv;
    char clock[16] = "";
    if (localtime_r(&t, &tmv)) strftime(clock, sizeof(clock), "%H:%M:%S", &tmv);
    int cl = ulen(clock);
    int cx = (g_w - cl) / 2;
    char iv[16];
    int secs = STEPS[u->step];
    if (secs < 120) snprintf(iv, sizeof(iv), " %ds ", secs);
    else snprintf(iv, sizeof(iv), " %dm ", secs / 60);
    int rw = 1 + ulen(iv) + 1 + 2 + 7 + 2 + 4 + 1;
    bool full_right = g_w - (cx + cl) - 2 >= rw;
    int x = g_w - 1;
    if (full_right) {
        x -= rw - 1;
        x += hot_word(x, 0, "r", "efresh");
        x += 2;
        x += put_str(x, 0, "-", 1, C_HOT, A_BOLD);
        x += put_str(x, 0, iv, 8, C_TEXT, 0);
        x += put_str(x, 0, "+", 1, C_HOT, A_BOLD);
        x += 2;
        hot_word(x, 0, "h", "elp");
    } else if (g_w - (cx + cl) - 2 >= 6) {
        hot_word(g_w - 5, 0, "h", "elp");
    }
    put_str(cx, 0, clock, cl, C_TITLE, A_BOLD);
    int lx = 1 + put_str(1, 0, "atop", 4, C_TITLE, A_BOLD) + 2;
    int lroom = cx - lx - 1;
    char st[300] = "";
    uint32_t sfg = C_DIM;
    if (u->err[0]) {
        snprintf(st, sizeof(st), "%s", u->err);
        sfg = C_ERR;
    } else if (u->child > 0) {
        snprintf(st, sizeof(st), "fetching\xe2\x80\xa6");
    }
    char hid[64] = "";
    for (int p = 0; p < g_npanels; p++) {
        if (u->hidden & (1u << p)) snprintf(hid + strlen(hid), sizeof(hid) - strlen(hid), "%s", SUPER[p]);
    }
    if (hid[0] && lroom > 10) {
        int k = put_str(lx, 0, "hidden ", lroom, C_DIM, 0);
        k += put_str(lx + k, 0, hid, lroom - k, C_HOT, A_BOLD);
        lx += k + 2;
        lroom -= k + 2;
    }
    if (dropped > 0 && lroom > 12) {
        char d[32];
        snprintf(d, sizeof(d), "+%d off-screen", dropped);
        int k = put_str(lx, 0, d, lroom, C_DIM, 0);
        lx += k + 2;
        lroom -= k + 2;
    }
    if (st[0] && lroom > 3) put_str(lx, 0, st, lroom, sfg, 0);
}

static void draw_help(void) {
    static const char *const K[][2] = {
        {"q", "quit"},
        {"r", "refresh now (daemon still rate-limits)"},
        {"1-4", "show or hide a panel"},
        {"e", "expand or collapse exhausted models"},
        {"+ -", "refresh interval"},
        {"h", "close help"},
    };
    int n = (int)(sizeof(K) / sizeof(K[0]));
    int w = 50 < g_w - 2 ? 50 : g_w - 2;
    int h = n + 4;
    if (h > g_h - 1) h = g_h - 1;
    int x = (g_w - w) / 2, y = 1 + (g_h - 1 - h) / 2;
    draw_frame(x, y, w, h, C_HOT);
    tag(x + 2, y, w - 4, "", "help", C_HOT, C_TITLE);
    for (int i = 0; i < n && 2 + i < h - 1; i++) {
        put_str(x + 3, y + 2 + i, K[i][0], 5, C_HOT, A_BOLD);
        put_str(x + 9, y + 2 + i, K[i][1], w - 11, C_TEXT, 0);
    }
}

static void draw_screen(const ui_t *u) {
    grid_clear();
    if (g_w < MIN_W || g_h < MIN_H) {
        char m[64];
        snprintf(m, sizeof(m), "terminal %dx%d too small", g_w, g_h);
        draw_center(g_h / 2, m, C_ERR);
        if (g_h / 2 + 1 < g_h) {
            snprintf(m, sizeof(m), "need %dx%d", MIN_W, MIN_H);
            draw_center(g_h / 2 + 1, m, C_DIM);
        }
        return;
    }
    int dropped = 0;
    if (u->resp) {
        build_model(u->resp, clock_ms(), u->expanded);
        int g = 1;
        dropped = layout(g_w, g_h, u->hidden, &g);
        for (int i = 0; i < g_nboxes; i++) {
            if (g_boxes[i].shown) draw_box(&g_boxes[i], u->expanded, g);
        }
        if (!g_nboxes) draw_center(g_h / 2, "no accounts", C_DIM);
        else if (u->hidden && dropped == 0) {
            bool any = false;
            for (int i = 0; i < g_nboxes; i++) any |= g_boxes[i].shown;
            if (!any) draw_center(g_h / 2, "all panels hidden", C_DIM);
        }
    } else {
        draw_center(g_h / 2, u->err[0] ? u->err : "fetching quota\xe2\x80\xa6", u->err[0] ? C_ERR : C_DIM);
    }
    draw_header(u, dropped);
    if (u->help) draw_help();
}

static int to256(uint32_t rgb) {
    int r = (int)((rgb >> 16) & 255), g = (int)((rgb >> 8) & 255), b = (int)(rgb & 255);
    int mx = r > g ? (r > b ? r : b) : (g > b ? g : b);
    int mn = r < g ? (r < b ? r : b) : (g < b ? g : b);
    if (mx - mn < 12) {
        int gi = (r + g + b) / 3;
        return gi < 8 ? 16 : gi > 238 ? 231 : 232 + (gi - 8) / 10;
    }
    int ri = r < 48 ? 0 : r < 115 ? 1 : (r - 35) / 40;
    int gi = g < 48 ? 0 : g < 115 ? 1 : (g - 35) / 40;
    int bi = b < 48 ? 0 : b < 115 ? 1 : (b - 35) / 40;
    return 16 + 36 * ri + 6 * gi + bi;
}

static void sgr(sb_t *o, uint32_t fg, uint8_t at) {
    sb_puts(o, "\033[0");
    if (at & A_BOLD) sb_puts(o, ";1");
    uint32_t rgb = fg & 0xffffff;
    bool dim = (fg & DIMMED) || (at & A_DIM);
    if (!g_color && !dim && (fg & 0x1000000u) && !(at & A_BOLD)) {
        int lum = (int)(((rgb >> 16) & 255) * 3 + ((rgb >> 8) & 255) * 6 + (rgb & 255)) / 10;
        dim = lum < 170;
    }
    if (dim) sb_puts(o, ";2");
    if (g_color && (fg & 0x1000000u)) {
        if (g_truecolor) sb_printf(o, ";38;2;%u;%u;%u", (rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);
        else sb_printf(o, ";38;5;%d", to256(rgb));
    }
    sb_putc(o, 'm');
}

static void put_utf8(sb_t *o, uint32_t cp) {
    char b[4];
    if (cp < 0x80) {
        sb_putc(o, (char)cp);
        return;
    }
    if (cp < 0x800) {
        b[0] = (char)(0xc0 | (cp >> 6));
        b[1] = (char)(0x80 | (cp & 63));
        sb_putn(o, b, 2);
    } else if (cp < 0x10000) {
        b[0] = (char)(0xe0 | (cp >> 12));
        b[1] = (char)(0x80 | ((cp >> 6) & 63));
        b[2] = (char)(0x80 | (cp & 63));
        sb_putn(o, b, 3);
    } else {
        b[0] = (char)(0xf0 | (cp >> 18));
        b[1] = (char)(0x80 | ((cp >> 12) & 63));
        b[2] = (char)(0x80 | ((cp >> 6) & 63));
        b[3] = (char)(0x80 | (cp & 63));
        sb_putn(o, b, 4);
    }
}

static void flush(sb_t *o) {
    if (g_full) sb_puts(o, "\033[0m\033[H\033[2J");
    int cx = -1, cy = -1;
    uint32_t cfg = 0xffffffffu;
    int cat = -1;
    for (int y = 0; y < g_h; y++) {
        for (int x = 0; x < g_w; x++) {
            cell_t *b = &g_back[y * g_w + x], *f = &g_front[y * g_w + x];
            if (!g_full && b->cp == f->cp && b->fg == f->fg && b->at == f->at) continue;
            if (g_full && b->cp == ' ' && !b->fg && !b->at) {
                *f = *b;
                continue;
            }
            if (cy != y || cx != x) sb_printf(o, "\033[%d;%dH", y + 1, x + 1);
            if (b->fg != cfg || b->at != cat) {
                sgr(o, b->fg, b->at);
                cfg = b->fg;
                cat = b->at;
            }
            put_utf8(o, b->cp);
            cx = x + 1;
            cy = y;
            *f = *b;
        }
    }
    if (cat >= 0) sb_puts(o, "\033[0m");
    g_full = false;
}

static void term_size(int *w, int *h) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *w = ws.ws_col > MAX_COLS ? MAX_COLS : ws.ws_col;
        *h = ws.ws_row > MAX_LINES ? MAX_LINES : ws.ws_row;
    } else {
        *w = 80;
        *h = 24;
    }
}

static void start_fetch(ui_t *u) {
    int p[2];
    if (pipe(p) != 0) {
        snprintf(u->err, sizeof(u->err), "pipe: %s", strerror(errno));
        u->next_fetch = now_ms() + 5000;
        return;
    }
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        snprintf(u->err, sizeof(u->err), "fork: %s", strerror(errno));
        u->next_fetch = now_ms() + 5000;
        return;
    }
    if (pid == 0) {
        g_alt = 0;
        g_tio_saved = 0;
        g_raw_set = 0;
        g_child_pid = 0;
        static const int sigs[] = {SIGINT, SIGTERM, SIGHUP, SIGTSTP, SIGWINCH, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
        for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) signal(sigs[i], SIG_DFL);
        signal(SIGPIPE, SIG_IGN);
        close(p[0]);
        int dn = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (dn >= 0) {
            dup2(dn, STDIN_FILENO);
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
        }
        char err[256] = "";
        jval_t *r = fetch(u->sock, u->direct, err, sizeof(err));
        if (!r) {
            r = j_obj();
            j_obj_set(r, "ok", j_bool(false));
            j_obj_set(r, "error", j_str(err[0] ? err : "quota request failed"));
        }
        char *s = j_show(r);
        if (s) {
            emit_all(p[1], s, strlen(s));
            emit_all(p[1], "\n", 1);
        }
        _exit(0);
    }
    close(p[1]);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    u->child = pid;
    g_child_pid = pid;
    u->cfd = p[0];
    u->cbuf.len = 0;
    if (u->cbuf.data) u->cbuf.data[0] = '\0';
}

static void finish_fetch(ui_t *u) {
    close(u->cfd);
    u->cfd = -1;
    while (waitpid(u->child, NULL, 0) < 0 && errno == EINTR) {
    }
    u->child = -1;
    g_child_pid = 0;
    char *nl = u->cbuf.data ? memchr(u->cbuf.data, '\n', u->cbuf.len) : NULL;
    if (nl) *nl = '\0';
    jval_t *r = nl ? j_parse(u->cbuf.data) : NULL;
    const jval_t *ok = r ? j_obj_get(r, "ok") : NULL;
    if (!r) {
        snprintf(u->err, sizeof(u->err), "quota response unreadable");
    } else if (ok && ok->type == J_BOOL && ok->b) {
        j_free(u->resp);
        u->resp = r;
        r = NULL;
        u->err[0] = '\0';
        quota_cache_absorb(u->resp);
        hist_record(u->resp, clock_ms());
    } else {
        clean_copy(u->err, sizeof(u->err), j_str_at(r, "error")[0] ? j_str_at(r, "error") : "quota request failed");
    }
    j_free(r);
    u->last_done = now_ms();
    u->next_fetch = u->last_done + (int64_t)STEPS[u->step] * 1000;
}

static void read_child(ui_t *u) {
    char buf[8192];
    for (;;) {
        ssize_t r = read(u->cfd, buf, sizeof(buf));
        if (r > 0) {
            if (u->cbuf.len + (size_t)r <= RESP_MAX) sb_putn(&u->cbuf, buf, (size_t)r);
            if (memchr(buf, '\n', (size_t)r)) break;
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        break;
    }
    finish_fetch(u);
}

static bool esc_pending(const char *buf, ssize_t n) {
    ssize_t e = n - 1;
    while (e >= 0 && buf[e] != 27) e--;
    if (e < 0) return false;
    if (e == n - 1) return true;
    if (buf[e + 1] != '[' && buf[e + 1] != 'O') return false;
    for (ssize_t i = e + 2; i < n; i++) {
        if ((unsigned char)buf[i] >= 0x40 && (unsigned char)buf[i] <= 0x7e) return false;
    }
    return true;
}

static bool handle_keys(ui_t *u, const char *buf, ssize_t n) {
    for (ssize_t i = 0; i < n; i++) {
        char c = buf[i];
        if (c == 27) {
            if (i + 1 < n && (buf[i + 1] == '[' || buf[i + 1] == 'O')) {
                i += 2;
                while (i < n && !((unsigned char)buf[i] >= 0x40 && (unsigned char)buf[i] <= 0x7e)) i++;
            } else {
                u->help = false;
            }
            continue;
        }
        switch (c) {
        case 'q':
        case 'Q':
        case 4:
            return true;
        case 'r':
        case 'R':
            if (u->child < 0) u->next_fetch = 0;
            break;
        case '1':
        case '2':
        case '3':
        case '4':
            u->hidden ^= 1u << (c - '1');
            break;
        case 'h':
        case 'H':
        case '?':
            u->help = !u->help;
            break;
        case 'e':
        case 'E':
            u->expanded = !u->expanded;
            break;
        case '+':
        case '=':
        case '-':
        case '_': {
            int s = u->step + ((c == '+' || c == '=') ? 1 : -1);
            int ns = (int)(sizeof(STEPS) / sizeof(STEPS[0]));
            u->step = s < 0 ? 0 : s >= ns ? ns - 1 : s;
            if (u->child < 0 && u->last_done) u->next_fetch = u->last_done + (int64_t)STEPS[u->step] * 1000;
            break;
        }
        default:
            break;
        }
    }
    return false;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    static const int fatal[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
    for (size_t i = 0; i < sizeof(fatal) / sizeof(fatal[0]); i++) sigaction(fatal[i], &sa, NULL);
    sa.sa_handler = on_tstp;
    sigaction(SIGTSTP, &sa, NULL);
    sa.sa_handler = on_winch;
    sigaction(SIGWINCH, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static int tui(const char *sock_path, bool force_direct) {
    const char *nc = getenv("NO_COLOR");
    const char *term = getenv("TERM");
    const char *ct = getenv("COLORTERM");
    g_color = !(nc && nc[0]) && !(term && strcmp(term, "dumb") == 0);
    g_truecolor = ct && (strstr(ct, "truecolor") || strstr(ct, "24bit"));
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &g_tio) == 0) {
        struct termios raw = g_tio;
        raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
            g_raw = raw;
            g_raw_set = 1;
            g_tio_saved = 1;
        }
    }
    install_signals();
    atexit(term_restore);
    if (write(STDOUT_FILENO, ALT_ON, sizeof(ALT_ON) - 1) > 0) g_alt = 1;

    ui_t u;
    memset(&u, 0, sizeof(u));
    u.sock = sock_path;
    u.direct = force_direct;
    u.child = -1;
    u.cfd = -1;
    u.step = 3;
    sb_init(&u.cbuf);
    char hp[1024];
    if (hist_path(hp, sizeof(hp))) hist_load(hp, clock_ms());
    int w = 0, h = 0;
    term_size(&w, &h);
    grid_resize(w, h);
    bool use_in = isatty(STDIN_FILENO);
    sb_t out;
    sb_init(&out);
    for (;;) {
        if (g_winch || g_resumed) {
            g_winch = 0;
            g_resumed = 0;
            term_size(&w, &h);
            if (w != g_w || h != g_h) grid_resize(w, h);
            g_full = true;
        }
        if (u.child < 0 && now_ms() >= u.next_fetch) start_fetch(&u);
        draw_screen(&u);
        out.len = 0;
        flush(&out);
        if (out.len) emit_all(STDOUT_FILENO, out.data, out.len);
        int64_t t = now_ms();
        int timeout = (int)(1000 - (clock_ms() % 1000));
        if (g_now_fixed > 0) timeout = 1000;
        if (u.child < 0 && u.next_fetch - t < timeout) timeout = u.next_fetch - t < 0 ? 0 : (int)(u.next_fetch - t);
        struct pollfd p[2];
        int np = 0, in_i = -1, ch_i = -1;
        if (use_in) {
            p[np].fd = STDIN_FILENO;
            p[np].events = POLLIN;
            p[np].revents = 0;
            in_i = np++;
        }
        if (u.cfd >= 0) {
            p[np].fd = u.cfd;
            p[np].events = POLLIN;
            p[np].revents = 0;
            ch_i = np++;
        }
        int pr = poll(p, (nfds_t)np, timeout);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (in_i >= 0 && (p[in_i].revents & POLLIN)) {
            char buf[64];
            ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r == 0) use_in = false;
            while (r > 0 && (size_t)r < sizeof(buf) && esc_pending(buf, r)) {
                struct pollfd q = {STDIN_FILENO, POLLIN, 0};
                if (poll(&q, 1, 50) <= 0) break;
                ssize_t more = read(STDIN_FILENO, buf + r, sizeof(buf) - (size_t)r);
                if (more <= 0) break;
                r += more;
            }
            if (r > 0 && handle_keys(&u, buf, r)) break;
        } else if (in_i >= 0 && (p[in_i].revents & (POLLHUP | POLLERR | POLLNVAL))) {
            use_in = false;
        }
        if (ch_i >= 0 && (p[ch_i].revents & (POLLIN | POLLHUP | POLLERR))) read_child(&u);
    }
    sb_free(&out);
    term_restore();
    if (u.cfd >= 0) close(u.cfd);
    if (u.child > 0) {
        g_child_pid = 0;
        kill(u.child, SIGTERM);
        while (waitpid(u.child, NULL, 0) < 0 && errno == EINTR) {
        }
    }
    j_free(u.resp);
    sb_free(&u.cbuf);
    return 0;
}

int atop_main(int argc, char **argv, const char *sock_path, bool force_direct, bool one_shot) {
    bool json = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json = true;
        } else if (strcmp(argv[i], "--once") == 0) {
            one_shot = true;
        } else if (strcmp(argv[i], "--direct") == 0) {
            force_direct = true;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            sock_path = argv[++i];
        } else if (strcmp(argv[i], "--now-ms") == 0 && i + 1 < argc) {
            if (!str_to_i64(argv[++i], &g_now_fixed) || g_now_fixed <= 0) {
                fprintf(stderr, "atop: bad --now-ms %s\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fputs(ATOP_USAGE, stdout);
            return 0;
        } else {
            fprintf(stderr, "atop: unknown argument %s\n%s", argv[i], ATOP_USAGE);
            return 2;
        }
    }
    if (json || one_shot || !isatty(STDOUT_FILENO)) return once(sock_path, force_direct, json);
    return tui(sock_path, force_direct);
}
