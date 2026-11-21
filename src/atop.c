#define _POSIX_C_SOURCE 200809L

#include "daemon.h"
#include "json.h"
#include "quota.h"
#include "util.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define ATOP_REDRAW_MS 60000
#define ATOP_RPC_MS 45000
#define ATOP_LINES 256
#define ATOP_BAR 10

static const char ATOP_USAGE[] =
    "usage: atop [--json] [--once] [--socket PATH] [--direct]\n"
    "       auth-router quota [--json]\n";

static const char ALT_ON[] = "\033[?1049h\033[?25l";
static const char ALT_OFF[] = "\033[?25h\033[?1049l";

static struct termios g_tio;
static volatile sig_atomic_t g_tio_saved;
static volatile sig_atomic_t g_alt;

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

static void term_restore(void) {
    if (g_tio_saved) tcsetattr(STDIN_FILENO, TCSANOW, &g_tio);
    if (g_alt && write(STDOUT_FILENO, ALT_OFF, sizeof(ALT_OFF) - 1) < 0) {
        g_alt = 0;
    }
    g_alt = 0;
}

static struct termios g_raw;
static volatile sig_atomic_t g_raw_set;
static volatile sig_atomic_t g_resumed;

static void on_sig(int sig) {
    term_restore();
    signal(sig, SIG_DFL);
    raise(sig);
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

static void render(const jval_t *resp, const char *fail_msg, bool tty, sb_t *out) {
    int64_t now = now_ms();
    if (tty) {
        sb_puts(out, "\033[H\033[2J");
        time_t t = (time_t)(now / 1000);
        struct tm tmv;
        char clock[16] = "";
        if (localtime_r(&t, &tmv)) strftime(clock, sizeof(clock), "%H:%M:%S", &tmv);
        sb_printf(out, "\033[1matop\033[0m  %s  refresh %ds  q quit\n\n", clock, ATOP_REDRAW_MS / 1000);
    }
    if (!resp) {
        char msg[256];
        clean_copy(msg, sizeof(msg), fail_msg);
        sb_printf(out, "atop: %s\n", msg);
        return;
    }
    if (j_obj_get(resp, "ok") && !j_obj_get(resp, "ok")->b) {
        char msg[256];
        clean_copy(msg, sizeof(msg), j_str_at(resp, "error"));
        sb_printf(out, "atop: %s\n", msg);
        return;
    }
    static line_t lines[ATOP_LINES];
    size_t n = build_lines(resp, lines, ATOP_LINES, now);
    size_t wp = strlen("PROVIDER"), wa = strlen("ACCOUNT"), ww = strlen("WINDOW"), wr = strlen("RESETS");
    for (size_t i = 0; i < n; i++) {
        if (strlen(lines[i].prov) > wp) wp = strlen(lines[i].prov);
        if (strlen(lines[i].acct) > wa) wa = strlen(lines[i].acct);
        if (strlen(lines[i].win) > ww) ww = strlen(lines[i].win);
        if (strlen(lines[i].resets) > wr) wr = strlen(lines[i].resets);
    }
    if (tty) sb_puts(out, "\033[2m");
    pad(out, "PROVIDER", wp + 2);
    pad(out, "ACCOUNT", wa + 2);
    pad(out, "WINDOW", ww + 2);
    sb_puts(out, " USED  ");
    pad(out, "", ATOP_BAR + 2);
    pad(out, "RESETS", wr + 2);
    sb_puts(out, "NOTE");
    if (tty) sb_puts(out, "\033[0m");
    sb_putc(out, '\n');
    for (size_t i = 0; i < n; i++) {
        const line_t *l = &lines[i];
        if (i > 0 && l->prov[0]) sb_putc(out, '\n');
        pad(out, l->prov, wp + 2);
        pad(out, l->acct, wa + 2);
        if (tty && l->err) sb_puts(out, "\033[31m");
        pad(out, l->win, ww + 2);
        if (tty && l->err) sb_puts(out, "\033[0m");
        const char *color = "";
        if (tty && l->has_pct) color = l->pct >= 90 ? "\033[31m" : l->pct >= 70 ? "\033[33m" : "\033[32m";
        sb_puts(out, color);
        char used[16];
        snprintf(used, sizeof(used), "%5s", l->used);
        sb_puts(out, used);
        sb_puts(out, "  ");
        if (l->has_pct) {
            int64_t fill = (l->pct * ATOP_BAR + 50) / 100;
            if (fill < 0) fill = 0;
            if (fill > ATOP_BAR) fill = ATOP_BAR;
            for (int64_t k = 0; k < ATOP_BAR; k++) {
                if (tty) sb_puts(out, k < fill ? "\xe2\x96\x88" : "\xe2\x96\x91");
                else sb_putc(out, k < fill ? '#' : '-');
            }
        } else {
            pad(out, "", ATOP_BAR);
        }
        if (color[0]) sb_puts(out, "\033[0m");
        sb_puts(out, "  ");
        pad(out, l->resets, wr + 2);
        if (tty && l->note[0] && !l->err) sb_puts(out, "\033[2m");
        sb_puts(out, l->note);
        if (tty && l->note[0] && !l->err) sb_puts(out, "\033[0m");
        size_t len = out->len;
        while (len > 0 && out->data[len - 1] == ' ') len--;
        out->len = len;
        out->data[len] = '\0';
        sb_putc(out, '\n');
    }
}

static void emit(const sb_t *sb) {
    size_t off = 0;
    while (sb->data && off < sb->len) {
        ssize_t w = write(STDOUT_FILENO, sb->data + off, sb->len - off);
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
        render(resp, NULL, false, &sb);
        fflush(stdout);
        emit(&sb);
        sb_free(&sb);
    } else {
        fprintf(stderr, "atop: %s\n", j_str_at(resp, "error")[0] ? j_str_at(resp, "error") : "quota request failed");
    }
    j_free(resp);
    return good ? 0 : 1;
}

static bool wait_for_quit(int64_t ms) {
    int64_t until = now_ms() + ms;
    bool use_in = isatty(STDIN_FILENO);
    for (;;) {
        int64_t rem = until - now_ms();
        if (rem <= 0 || g_resumed) {
            g_resumed = 0;
            return false;
        }
        struct pollfd p;
        p.fd = STDIN_FILENO;
        p.events = POLLIN;
        p.revents = 0;
        int pr = poll(use_in ? &p : NULL, use_in ? 1 : 0, rem > 1000 ? 1000 : (int)rem);
        if (pr < 0 && errno != EINTR) return true;
        if (pr > 0 && (p.revents & POLLIN)) {
            char buf[64];
            ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r == 0) use_in = false;
            for (ssize_t i = 0; i < r; i++) {
                if (buf[i] == 'q' || buf[i] == 'Q' || buf[i] == 4) return true;
            }
        } else if (pr > 0 && (p.revents & (POLLHUP | POLLERR | POLLNVAL))) {
            use_in = false;
        }
    }
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
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fputs(ATOP_USAGE, stdout);
            return 0;
        } else {
            fprintf(stderr, "atop: unknown argument %s\n%s", argv[i], ATOP_USAGE);
            return 2;
        }
    }
    if (json || one_shot || !isatty(STDOUT_FILENO)) return once(sock_path, force_direct, json);

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
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_tstp;
    sigaction(SIGTSTP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    if (write(STDOUT_FILENO, ALT_ON, sizeof(ALT_ON) - 1) > 0) g_alt = 1;

    for (;;) {
        char err[256];
        err[0] = '\0';
        jval_t *resp = fetch(sock_path, force_direct, err, sizeof(err));
        sb_t sb;
        sb_init(&sb);
        render(resp, err[0] ? err : "quota request failed", true, &sb);
        emit(&sb);
        sb_free(&sb);
        j_free(resp);
        if (wait_for_quit(ATOP_REDRAW_MS)) break;
    }
    term_restore();
    return 0;
}
