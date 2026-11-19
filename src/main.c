#define _POSIX_C_SOURCE 200809L

#include "daemon.h"
#include "http.h"
#include "json.h"
#include "oauth.h"
#include "policy.h"
#include "store.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define AUTH_ROUTER_VERSION "0.1.0"

static const char *USAGE =
    "usage: auth-router [--socket PATH] [--state-dir PATH] [--direct] <command> [args]\n"
    "commands:\n"
    "  daemon [--socket PATH] [--restricted-socket PATH] [--state-dir PATH] [--no-bg-refresh]\n"
    "  ping\n"
    "  status [--json]\n"
    "  list [--json]\n"
    "  add <provider> [name] <key>\n"
    "  remove <name>\n"
    "  order <name...>\n"
    "  top <name>\n"
    "  rotate [provider]\n"
    "  cool <id> [model] <duration|ms> [--status N]\n"
    "  token <provider> [model] [--prefer ID] [--top ID] [--rotate-from ID] [--now-ms MS] [--json]\n"
    "  route <provider:model ...> [--exclude-provider P] [--prefer ID] [--top ID] [--rotate-from ID] [--now-ms MS] [--json]\n"
    "  login [provider] [name]\n"
    "  keys | key <provider> [name] [key] | logout <name> | unkey <name> | acp-confirm <name> <email>\n"
    "  json <subcommand> [args]\n";

static void fail(const char *msg) {
    fprintf(stderr, "auth-router: %s\n", msg ? msg : "error");
}

static bool capture_cmd_stdout(char *const argv[], char **out, char *err, size_t err_n) {
    *out = NULL;
    int pfd[2];
    if (pipe(pfd) != 0) {
        snprintf(err, err_n, "pipe: %s", strerror(errno));
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        snprintf(err, err_n, "fork: %s", strerror(errno));
        return false;
    }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    sb_t sb;
    sb_init(&sb);
    char buf[4096];
    for (;;) {
        ssize_t r = read(pfd[0], buf, sizeof(buf));
        if (r > 0) sb_putn(&sb, buf, (size_t)r);
        else if (r == 0) break;
        else if (errno != EINTR) break;
    }
    close(pfd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        sb_free(&sb);
        snprintf(err, err_n, "command %s exited with status %d", argv[0], WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return false;
    }
    *out = sb.data;
    return true;
}

static bool run_cmd_interactive(char *const argv[], char *err, size_t err_n) {
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(err, err_n, "fork: %s", strerror(errno));
        return false;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        snprintf(err, err_n, "%s failed", argv[0]);
        return false;
    }
    return true;
}

static bool extract_antigravity_snapshots(str_list_t *emails, str_list_t *blobs, char *err, size_t err_n) {
    memset(emails, 0, sizeof(*emails));
    memset(blobs, 0, sizeof(*blobs));
    char *argv[] = {"omp", "auth", "export", NULL};
    char *raw = NULL;
    if (!capture_cmd_stdout(argv, &raw, err, err_n)) return false;
    jval_t *root = j_parse(raw ? raw : "");
    free(raw);
    if (!root || root->type != J_OBJ) {
        j_free(root);
        snprintf(err, err_n, "invalid JSON from omp auth export");
        return false;
    }
    jval_t *creds = j_obj_get(root, "credentials");
    if (creds && creds->type == J_ARR) {
        for (size_t i = 0; i < creds->arr_len; i++) {
            const jval_t *it = creds->arr[i];
            if (!it || it->type != J_OBJ) continue;
            if (strcmp(j_str_at(it, "provider"), "antigravity-cli") != 0) continue;
            jval_t *cred = j_obj_get(it, "credential");
            if (!cred || cred->type != J_OBJ) continue;
            const char *em = j_str_at(cred, "email");
            char *blob = j_show(cred);
            str_list_push(emails, em);
            str_list_push(blobs, blob ? blob : "");
            free(blob);
        }
    }
    j_free(root);
    return true;
}

static bool cmd_acp_signin_native(const char *name, char *err, size_t err_n) {
    if (!acp_name_ok(name)) {
        snprintf(err, err_n, "invalid Antigravity account name: %s", name);
        return false;
    }
    jval_t *existing = NULL;
    if (!ak_get(name, &existing, err, err_n)) return false;
    if (!existing) {
        if (!acp_add(name, err, err_n)) return false;
    } else {
        bool is_a = acp_is(name, existing);
        j_free(existing);
        if (!is_a) {
            snprintf(err, err_n, "%s is already used by another provider", name);
            return false;
        }
    }
    if (!acp_activate(name, err, err_n)) return false;

    str_list_t before_em = {0};
    str_list_t before_bl = {0};
    if (!extract_antigravity_snapshots(&before_em, &before_bl, err, err_n)) return false;

    printf("Signing %s in with omp login antigravity-cli\n", name);
    char *login_argv[] = {"omp", "login", "antigravity-cli", NULL};
    if (!run_cmd_interactive(login_argv, err, err_n)) {
        str_list_free(&before_em);
        str_list_free(&before_bl);
        snprintf(err, err_n, "Google sign-in for %s did not finish; %s is not active.", name, name);
        return false;
    }

    str_list_t after_em = {0};
    str_list_t after_bl = {0};
    if (!extract_antigravity_snapshots(&after_em, &after_bl, err, err_n)) {
        str_list_free(&before_em);
        str_list_free(&before_bl);
        return false;
    }

    char found_email[256];
    found_email[0] = '\0';
    int changed = 0;
    for (size_t i = 0; i < after_bl.len; i++) {
        bool existed = false;
        for (size_t j = 0; j < before_bl.len; j++) {
            if (strcmp(after_em.items[i], before_em.items[j]) == 0 &&
                strcmp(after_bl.items[i], before_bl.items[j]) == 0) {
                existed = true;
                break;
            }
        }
        if (!existed) {
            snprintf(found_email, sizeof(found_email), "%s", after_em.items[i]);
            changed++;
        }
    }

    str_list_free(&before_em);
    str_list_free(&before_bl);
    str_list_free(&after_em);
    str_list_free(&after_bl);

    if (changed != 1 || !found_email[0]) {
        snprintf(err, err_n, "Google sign-in for %s changed %d logins in omp; %s is unchanged.", name, changed, name);
        return false;
    }
    if (!acp_confirm(name, found_email, err, err_n)) return false;
    printf("%s is signed in as %s and is the active Antigravity account.\n", name, found_email);
    return true;
}

static bool call_router(const jval_t *req,
                        const char *sock_path,
                        bool force_direct,
                        jval_t **resp_out,
                        char *err,
                        size_t err_n) {
    *resp_out = NULL;
    if (!force_direct) {
        char derr[256];
        daemon_rpc_status_t st = daemon_rpc(sock_path, req, 30000, resp_out, derr, sizeof(derr));
        if (st == DAEMON_RPC_OK) return true;
        if (st == DAEMON_RPC_ERR) {
            snprintf(err, err_n, "%s", derr);
            return false;
        }
    }
    *resp_out = router_exec_direct(req, false);
    if (!*resp_out) {
        snprintf(err, err_n, "direct router execution failed");
        return false;
    }
    return true;
}

static bool resp_check_ok(const jval_t *resp, char *err, size_t err_n) {
    if (!resp || resp->type != J_OBJ) {
        snprintf(err, err_n, "invalid response");
        return false;
    }
    jval_t *ok = j_obj_get(resp, "ok");
    if (!ok || ok->type != J_BOOL || !ok->b) {
        const char *msg = j_str_at(resp, "error");
        snprintf(err, err_n, "%s", msg[0] ? msg : "operation failed");
        return false;
    }
    return true;
}

static void print_json(const jval_t *v) {
    char *s = j_show(v);
    if (s) {
        printf("%s\n", s);
        free(s);
    }
}

static bool parse_route_spec(const char *arg, char *prov, size_t prov_n, char *mod, size_t mod_n) {
    const char *colon = strchr(arg, ':');
    const char *slash = strchr(arg, '/');
    const char *sep = colon ? colon : slash;
    if (!sep) {
        snprintf(prov, prov_n, "%s", arg);
        mod[0] = '\0';
        return prov[0] != '\0';
    }
    size_t plen = (size_t)(sep - arg);
    if (plen == 0 || plen >= prov_n) return false;
    memcpy(prov, arg, plen);
    prov[plen] = '\0';
    snprintf(mod, mod_n, "%s", sep + 1);
    return true;
}

static bool cmd_json_dispatch(int argc, char **argv, const char *sock_path, bool force_direct, char *err, size_t err_n) {
    if (argc < 1) {
        snprintf(err, err_n, "json requires a subcommand");
        return false;
    }
    const char *sub = argv[0];
    jval_t *req = j_obj();
    j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));

    if (strcmp(sub, "list") == 0) {
        j_obj_set(req, "op", j_str("list"));
    } else if (strcmp(sub, "status") == 0) {
        j_obj_set(req, "op", j_str("status"));
    } else if (strcmp(sub, "top") == 0 && argc == 2) {
        j_obj_set(req, "op", j_str("top"));
        j_obj_set(req, "name", j_str(argv[1]));
    } else if (strcmp(sub, "order") == 0 && argc >= 2) {
        j_obj_set(req, "op", j_str("order"));
        jval_t *arr = j_arr();
        for (int i = 1; i < argc; i++) j_arr_push(arr, j_str(argv[i]));
        j_obj_set(req, "names", arr);
    } else if ((strcmp(sub, "logout") == 0 || strcmp(sub, "remove") == 0 || strcmp(sub, "key-rm") == 0) && argc == 2) {
        j_obj_set(req, "op", j_str("remove"));
        j_obj_set(req, "name", j_str(argv[1]));
    } else if ((strcmp(sub, "key-set") == 0 || strcmp(sub, "add") == 0) && (argc == 3 || argc == 4)) {
        j_obj_set(req, "op", j_str("add"));
        j_obj_set(req, "provider", j_str(argv[1]));
        j_obj_set(req, "name", j_str(argc == 4 ? argv[2] : argv[1]));
        j_obj_set(req, "key", j_str(argc == 4 ? argv[3] : argv[2]));
    } else if (strcmp(sub, "rotate") == 0) {
        j_obj_set(req, "op", j_str("rotate"));
        if (argc >= 2) j_obj_set(req, "provider", j_str(argv[1]));
    } else if (strcmp(sub, "cool") == 0 && (argc == 3 || argc == 4)) {
        j_obj_set(req, "op", j_str("cool"));
        j_obj_set(req, "id", j_str(argv[1]));
        if (argc == 3) {
            j_obj_set(req, "model", j_str(""));
            j_obj_set(req, "duration", j_str(argv[2]));
        } else {
            j_obj_set(req, "model", j_str(argv[2]));
            j_obj_set(req, "duration", j_str(argv[3]));
        }
    } else if (strcmp(sub, "token") == 0 && argc >= 2) {
        j_obj_set(req, "op", j_str("token"));
        j_obj_set(req, "provider", j_str(argv[1]));
        j_obj_set(req, "model", j_str(argc >= 3 ? argv[2] : ""));
    } else if (strcmp(sub, "antigravity") == 0 && argc == 2) {
        j_free(req);
        jval_t *e = NULL;
        if (!ak_get(argv[1], &e, err, err_n)) return false;
        bool is_a = e && acp_is(argv[1], e);
        j_free(e);
        if (!is_a) {
            snprintf(err, err_n, "%s is not an Antigravity ACP account", argv[1]);
            return false;
        }
        jval_t *out = j_obj();
        j_obj_set(out, "name", j_str(argv[1]));
        char dir[1024];
        acp_dir(argv[1], dir, sizeof(dir));
        j_obj_set(out, "dir", j_str(dir));
        print_json(out);
        j_free(out);
        return true;
    } else {
        j_free(req);
        snprintf(err, err_n, "unknown json subcommand: %s", sub);
        return false;
    }

    jval_t *resp = NULL;
    bool ok = call_router(req, sock_path, force_direct, &resp, err, err_n);
    j_free(req);
    if (!ok) return false;
    bool rok = resp_check_ok(resp, err, err_n);
    if (rok) print_json(resp);
    j_free(resp);
    return rok;
}

int main(int argc, char **argv) {
    const char *sock_path = NULL;
    const char *state_dir_arg = NULL;
    bool force_direct = false;

    int argi = 1;
    while (argi < argc) {
        if (strcmp(argv[argi], "--socket") == 0 && argi + 1 < argc) {
            sock_path = argv[argi + 1];
            argi += 2;
        } else if (strcmp(argv[argi], "--state-dir") == 0 && argi + 1 < argc) {
            state_dir_arg = argv[argi + 1];
            argi += 2;
        } else if (strcmp(argv[argi], "--direct") == 0) {
            force_direct = true;
            argi += 1;
        } else {
            break;
        }
    }

    if (state_dir_arg && state_dir_arg[0]) {
        state_dir_set_override(state_dir_arg);
    }

    if (argi >= argc || strcmp(argv[argi], "--help") == 0 || strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "help") == 0) {
        fputs(USAGE, stdout);
        return (argi >= argc) ? 1 : 0;
    }

    if (strcmp(argv[argi], "--version") == 0 || strcmp(argv[argi], "version") == 0) {
        printf("auth-router %s\n", AUTH_ROUTER_VERSION);
        return 0;
    }

    const char *cmd = argv[argi];
    int rest_c = argc - argi - 1;
    char **rest_v = argv + argi + 1;

    char err[512];
    err[0] = '\0';

    if (strcmp(cmd, "daemon") == 0) {
        daemon_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.socket_path = sock_path;
        cfg.state_dir_path = state_dir_arg;
        for (int i = 0; i < rest_c; i++) {
            if (strcmp(rest_v[i], "--socket") == 0 && i + 1 < rest_c) {
                cfg.socket_path = rest_v[++i];
            } else if (strcmp(rest_v[i], "--restricted-socket") == 0 && i + 1 < rest_c) {
                cfg.restricted_socket_path = rest_v[++i];
            } else if (strcmp(rest_v[i], "--restricted-mode") == 0 && i + 1 < rest_c) {
                const char *ms = rest_v[++i];
                char *end = NULL;
                unsigned long mv = strtoul(ms, &end, 8);
                if (!ms[0] || !end || *end != '\0' || mv == 0 || mv > 0777) {
                    snprintf(err, sizeof(err), "invalid octal mode for --restricted-mode: %s", ms);
                    fail(err);
                    return 1;
                }
                cfg.restricted_mode = (mode_t)mv;
            } else if (strcmp(rest_v[i], "--state-dir") == 0 && i + 1 < rest_c) {
                cfg.state_dir_path = rest_v[++i];
            } else if (strcmp(rest_v[i], "--no-bg-refresh") == 0) {
                cfg.no_bg_refresh = true;
            } else {
                snprintf(err, sizeof(err), "unknown daemon flag: %s", rest_v[i]);
                fail(err);
                return 1;
            }
        }
        int rc = daemon_run(&cfg, err, sizeof(err));
        if (rc != 0) fail(err);
        return rc;
    }

    if (strcmp(cmd, "ping") == 0) {
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("ping"));
        jval_t *resp = NULL;
        daemon_rpc_status_t st = daemon_rpc(sock_path, req, 5000, &resp, err, sizeof(err));
        j_free(req);
        if (st != DAEMON_RPC_OK) {
            fail(err);
            return 1;
        }
        bool ok = resp_check_ok(resp, err, sizeof(err));
        if (ok) print_json(resp);
        else fail(err);
        j_free(resp);
        return ok ? 0 : 1;
    }

    if (strcmp(cmd, "status") == 0 || strcmp(cmd, "list") == 0 || strcmp(cmd, "keys") == 0) {
        bool want_json = false;
        for (int i = 0; i < rest_c; i++) {
            if (strcmp(rest_v[i], "--json") == 0) want_json = true;
        }
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str(strcmp(cmd, "status") == 0 ? "status" : "list"));
        jval_t *resp = NULL;
        if (!call_router(req, sock_path, force_direct, &resp, err, sizeof(err))) {
            j_free(req);
            fail(err);
            return 1;
        }
        j_free(req);
        if (!resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        if (want_json) {
            print_json(resp);
        } else {
            jval_t *creds = j_obj_get(resp, "credentials");
            if (creds && creds->type == J_ARR) {
                for (size_t i = 0; i < creds->arr_len; i++) {
                    const jval_t *it = creds->arr[i];
                    if (strcmp(cmd, "keys") == 0 && strcmp(j_str_at(it, "kind"), "login") == 0) continue;
                    printf("%s\t%s\t%s\t%s\n",
                           j_str_at(it, "name"),
                           j_str_at(it, "provider"),
                           j_str_at(it, "kind"),
                           j_str_at(it, "health"));
                }
            }
            if (strcmp(cmd, "status") == 0) {
                jval_t *holds = j_obj_get(resp, "holds");
                if (holds && holds->type == J_ARR && holds->arr_len > 0) {
                    for (size_t i = 0; i < holds->arr_len; i++) {
                        const jval_t *h = holds->arr[i];
                        int64_t rem = 0;
                        j_int_at(h, "remaining_ms", &rem);
                        char sp[64];
                        auth_span(rem, sp, sizeof(sp));
                        printf("hold\t%s\t%s\t%s\n",
                               j_str_at(h, "id"),
                               j_str_at(h, "model")[0] ? j_str_at(h, "model") : "*",
                               sp);
                    }
                }
            }
        }
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "add") == 0 || strcmp(cmd, "key") == 0) {
        if (rest_c < 2 || rest_c > 3) {
            fail("usage: auth-router add <provider> [name] <key>");
            return 1;
        }
        const char *prov = rest_v[0];
        const char *name = (rest_c == 3) ? rest_v[1] : rest_v[0];
        const char *key = (rest_c == 3) ? rest_v[2] : rest_v[1];
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("add"));
        j_obj_set(req, "provider", j_str(prov));
        j_obj_set(req, "name", j_str(name));
        j_obj_set(req, "key", j_str(key));
        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        printf("%s\t%s\tapi_key\tready\n", name, prov);
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "remove") == 0 || strcmp(cmd, "logout") == 0 || strcmp(cmd, "unkey") == 0) {
        if (rest_c != 1) {
            fail("usage: auth-router remove <name>");
            return 1;
        }
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("remove"));
        j_obj_set(req, "name", j_str(rest_v[0]));
        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        printf("removed %s\n", rest_v[0]);
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "order") == 0 || strcmp(cmd, "top") == 0) {
        if (rest_c < 1) {
            fail("order/top requires at least one name");
            return 1;
        }
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        if (strcmp(cmd, "top") == 0) {
            j_obj_set(req, "op", j_str("top"));
            j_obj_set(req, "name", j_str(rest_v[0]));
        } else {
            j_obj_set(req, "op", j_str("order"));
            jval_t *arr = j_arr();
            for (int i = 0; i < rest_c; i++) j_arr_push(arr, j_str(rest_v[i]));
            j_obj_set(req, "names", arr);
        }
        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "rotate") == 0) {
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("rotate"));
        if (rest_c >= 1) j_obj_set(req, "provider", j_str(rest_v[0]));
        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        const char *rot = j_str_at(resp, "rotated");
        if (rot[0]) printf("rotated %s\n", rot);
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "cool") == 0) {
        const char *pos[4];
        int pos_c = 0;
        int64_t status = 429;
        for (int i = 0; i < rest_c; i++) {
            if (strcmp(rest_v[i], "--status") == 0 && i + 1 < rest_c) {
                str_to_i64(rest_v[++i], &status);
            } else if (pos_c < 4) {
                pos[pos_c++] = rest_v[i];
            }
        }
        if (pos_c < 2 || pos_c > 3) {
            fail("usage: auth-router cool <id> [model] <duration|ms> [--status N]");
            return 1;
        }
        const char *id = pos[0];
        const char *model = (pos_c == 3) ? pos[1] : "";
        const char *dur = (pos_c == 3) ? pos[2] : pos[1];

        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("cool"));
        j_obj_set(req, "id", j_str(id));
        j_obj_set(req, "model", j_str(model));
        j_obj_set(req, "duration", j_str(dur));
        j_obj_set(req, "status", j_int(status));
        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        print_json(resp);
        j_free(resp);
        return 0;
    }

    if (strcmp(cmd, "token") == 0) {
        const char *prov = NULL;
        const char *model = "";
        const char *prefer = "";
        const char *top = "";
        const char *rot = "";
        int64_t now_override = 0;
        bool want_json = false;
        for (int i = 0; i < rest_c; i++) {
            if (strcmp(rest_v[i], "--prefer") == 0 && i + 1 < rest_c) prefer = rest_v[++i];
            else if (strcmp(rest_v[i], "--top") == 0 && i + 1 < rest_c) top = rest_v[++i];
            else if (strcmp(rest_v[i], "--rotate-from") == 0 && i + 1 < rest_c) rot = rest_v[++i];
            else if (strcmp(rest_v[i], "--now-ms") == 0 && i + 1 < rest_c) str_to_i64(rest_v[++i], &now_override);
            else if (strcmp(rest_v[i], "--json") == 0) want_json = true;
            else if (!prov) prov = rest_v[i];
            else if (!model[0]) model = rest_v[i];
        }
        if (!prov) {
            fail("usage: auth-router token <provider> [model]");
            return 1;
        }
        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("token"));
        j_obj_set(req, "provider", j_str(prov));
        j_obj_set(req, "model", j_str(model));
        if (prefer[0]) j_obj_set(req, "prefer", j_str(prefer));
        if (top[0]) j_obj_set(req, "top", j_str(top));
        if (rot[0]) j_obj_set(req, "rotate_from", j_str(rot));
        if (now_override > 0) j_obj_set(req, "now_ms", j_int(now_override));

        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        int64_t status = 404;
        j_int_at(resp, "http_status", &status);
        if (want_json) {
            print_json(resp);
        } else if (status == 200) {
            const char *tok = j_str_at(resp, "access");
            if (!tok[0]) tok = j_str_at(resp, "api_key");
            if (!tok[0]) tok = j_str_at(resp, "acp_dir");
            printf("%s\n", tok);
        } else {
            int64_t rs = 0;
            j_int_at(resp, "retry_s", &rs);
            fprintf(stderr, "auth-router: no ready credential (http %ld, retry_s=%ld)\n", (long)status, (long)rs);
        }
        j_free(resp);
        return (status == 200) ? 0 : 1;
    }

    if (strcmp(cmd, "route") == 0) {
        jval_t *rarr = j_arr();
        const char *excl = "";
        const char *prefer = "";
        const char *top = "";
        const char *rot = "";
        int64_t now_override = 0;
        bool want_json = false;
        int64_t rank = 0;

        for (int i = 0; i < rest_c; i++) {
            if (strcmp(rest_v[i], "--exclude-provider") == 0 && i + 1 < rest_c) excl = rest_v[++i];
            else if (strcmp(rest_v[i], "--prefer") == 0 && i + 1 < rest_c) prefer = rest_v[++i];
            else if (strcmp(rest_v[i], "--top") == 0 && i + 1 < rest_c) top = rest_v[++i];
            else if (strcmp(rest_v[i], "--rotate-from") == 0 && i + 1 < rest_c) rot = rest_v[++i];
            else if (strcmp(rest_v[i], "--now-ms") == 0 && i + 1 < rest_c) str_to_i64(rest_v[++i], &now_override);
            else if (strcmp(rest_v[i], "--json") == 0) want_json = true;
            else {
                char p[128], m[128];
                if (!parse_route_spec(rest_v[i], p, sizeof(p), m, sizeof(m))) {
                    j_free(rarr);
                    fail("invalid route candidate (expected provider:model)");
                    return 1;
                }
                jval_t *ro = j_obj();
                j_obj_set(ro, "rank", j_int(rank++));
                j_obj_set(ro, "provider", j_str(p));
                j_obj_set(ro, "model", j_str(m));
                j_arr_push(rarr, ro);
            }
        }
        if (rarr->arr_len == 0) {
            j_free(rarr);
            fail("usage: auth-router route <provider:model ...>");
            return 1;
        }

        jval_t *req = j_obj();
        j_obj_set(req, "v", j_int(AUTH_ROUTER_WIRE_VERSION));
        j_obj_set(req, "op", j_str("route"));
        j_obj_set(req, "routes", rarr);
        if (excl[0]) j_obj_set(req, "exclude_provider", j_str(excl));
        if (prefer[0]) j_obj_set(req, "prefer", j_str(prefer));
        if (top[0]) j_obj_set(req, "top", j_str(top));
        if (rot[0]) j_obj_set(req, "rotate_from", j_str(rot));
        if (now_override > 0) j_obj_set(req, "now_ms", j_int(now_override));

        jval_t *resp = NULL;
        bool ok = call_router(req, sock_path, force_direct, &resp, err, sizeof(err));
        j_free(req);
        if (!ok || !resp_check_ok(resp, err, sizeof(err))) {
            j_free(resp);
            fail(err);
            return 1;
        }
        int64_t status = 404;
        j_int_at(resp, "http_status", &status);
        if (want_json) {
            print_json(resp);
        } else if (status == 200) {
            bool fb = j_obj_get(resp, "is_fallback") && j_obj_get(resp, "is_fallback")->b;
            int64_t pr = 0;
            j_int_at(resp, "primary_retry_ms", &pr);
            printf("%s\t%s\t%s\tfallback=%s\tprimary_retry_ms=%ld\n",
                   j_str_at(resp, "provider"),
                   j_str_at(resp, "model"),
                   j_str_at(resp, "login_id"),
                   fb ? "true" : "false",
                   (long)pr);
        } else {
            int64_t rs = 0;
            j_int_at(resp, "retry_s", &rs);
            fprintf(stderr, "auth-router: no ready route (http %ld, retry_s=%ld)\n", (long)status, (long)rs);
        }
        j_free(resp);
        return (status == 200) ? 0 : 1;
    }

    if (strcmp(cmd, "login") == 0) {
        bool ok = false;
        if (rest_c == 1) {
            bool is_l = false;
            if (auth_is_login(rest_v[0], &is_l, err, sizeof(err))) {
                if (is_l) {
                    ok = auth_login_interactive(rest_v[0], err, sizeof(err));
                } else {
                    jval_t *e = NULL;
                    if (ak_get(rest_v[0], &e, err, sizeof(err))) {
                        if (e) {
                            const char *t = j_str_at(e, "type");
                            if (strcmp(t, "acp") == 0) {
                                ok = cmd_acp_signin_native(rest_v[0], err, sizeof(err));
                            } else if (strcmp(t, "oauth") == 0) {
                                char p[128];
                                snprintf(p, sizeof(p), "%s", ak_provider(rest_v[0], e));
                                ok = oa_login_named_interactive(p, rest_v[0], err, sizeof(err));
                            } else {
                                snprintf(err, sizeof(err), "%s is an API key", rest_v[0]);
                            }
                            j_free(e);
                        } else if (strcmp(rest_v[0], ACP_PROVIDER) == 0) {
                            snprintf(err, sizeof(err), "name an Antigravity account: auth-router login %s NAME", ACP_PROVIDER);
                        } else if (oa_known(rest_v[0])) {
                            ok = oa_login_named_interactive(rest_v[0], rest_v[0], err, sizeof(err));
                        } else {
                            ok = auth_login_interactive(rest_v[0], err, sizeof(err));
                        }
                    }
                }
            }
        } else if (rest_c == 2) {
            if (strcmp(rest_v[0], ACP_PROVIDER) == 0) {
                ok = cmd_acp_signin_native(rest_v[1], err, sizeof(err));
            } else if (strcmp(rest_v[0], "anthropic") == 0) {
                ok = auth_login_interactive(rest_v[1], err, sizeof(err));
            } else if (oa_known(rest_v[0])) {
                if (oa_login_named_interactive(rest_v[0], rest_v[1], err, sizeof(err))) {
                    char id[256];
                    auth_credential_id(rest_v[0], rest_v[1], id, sizeof(id));
                    auth_forget(id, err, sizeof(err));
                    printf("%s\toauth\tready\tprovider %s\n", rest_v[1], rest_v[0]);
                    ok = true;
                }
            } else {
                snprintf(err, sizeof(err), "unknown provider: %s", rest_v[0]);
            }
        } else {
            snprintf(err, sizeof(err), "usage: auth-router login [provider] <name>");
        }
        if (!ok) {
            fail(err);
            return 1;
        }
        return 0;
    }

    if (strcmp(cmd, "acp-confirm") == 0 && rest_c == 2) {
        if (!acp_confirm(rest_v[0], rest_v[1], err, sizeof(err))) {
            fail(err);
            return 1;
        }
        printf("%s is signed in as %s and is the active Antigravity account.\n", rest_v[0], rest_v[1]);
        return 0;
    }

    if (strcmp(cmd, "json") == 0) {
        if (!cmd_json_dispatch(rest_c, rest_v, sock_path, force_direct, err, sizeof(err))) {
            fail(err);
            return 1;
        }
        return 0;
    }

    snprintf(err, sizeof(err), "unknown command: %s", cmd);
    fail(err);
    return 1;
}
