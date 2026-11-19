#ifndef OAUTH_H
#define OAUTH_H

#include "json.h"
#include "store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTH_CLIENT_ID "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
#define AUTH_AUTHORIZE_URL "https://claude.ai/oauth/authorize"
#define AUTH_COPY_REDIRECT "https://platform.claude.com/oauth/code/callback"
#define AUTH_CALLBACK_PATH "/callback"
#define AUTH_TOKEN_URL "https://platform.claude.com/v1/oauth/token"
#define AUTH_AGENT "claude-cli/2.1.280"
#define AUTH_MARGIN_MS (5 * 60 * 1000)
#define AUTH_COOLDOWN_MS (60 * 1000)
#define AUTH_WAIT_MS (5 * 60 * 1000)

typedef struct {
    char *access;
    char *refresh;
    int64_t expires;
    jval_t *extra;
} oa_tok_t;

typedef struct {
    char code[256];
    char user[128];
    char url[512];
    int64_t interval;
    int64_t expires;
} oa_dev_t;

void oa_tok_free(oa_tok_t *t);

bool oa_known(const char *id);
const char *oa_flow_kind(const char *id);

void auth_link(const char *redirect, const char *challenge, const char *state, sb_t *out);
bool auth_code_parse(const char *heard, const char *verifier, char *code_out, size_t code_n, char *state_out, size_t state_n, char *err, size_t err_n);
bool auth_complete(const login_t *current, const char *code, const char *state, const char *redirect, bool quiet, char *err, size_t err_n);
bool auth_fresh(const login_t *l, login_t *out, char *err, size_t err_n);
bool auth_login_interactive(const char *name, char *err, size_t err_n);

bool oa_load(const char *name, oa_tok_t *out, bool *found, char *err, size_t err_n);
bool oa_save_named(const char *provider, const char *name, const oa_tok_t *t, char *err, size_t err_n);
bool oa_fresh(const oa_tok_t *t, int64_t now);
bool oa_freshen_at(const char *name, const oa_tok_t *stored, int64_t at_ms, oa_tok_t *out, char *err, size_t err_n);

bool oa_flow_start_named(const char *provider, const char *name, oa_dev_t *out, char *err, size_t err_n);
int oa_flow_poll(const char *name, int64_t *interval_out, char *err, size_t err_n);
bool oa_login_named_interactive(const char *provider, const char *name, char *err, size_t err_n);

#endif
