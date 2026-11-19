#ifndef STORE_H
#define STORE_H

#include "json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ACP_PROVIDER "antigravity-acp"

typedef struct {
    char *name;
    char *access;
    char *refresh;
    int64_t expires;
    char *verifier;
} login_t;

typedef struct {
    login_t *items;
    size_t len;
    size_t cap;
} login_list_t;

typedef struct {
    char *id;
    char *model;
    int64_t until;
    bool reset;
} hold_t;

typedef struct {
    hold_t *items;
    size_t len;
    size_t cap;
} hold_list_t;

typedef struct {
    char *id;
    char *model;
} unavail_t;

typedef struct {
    unavail_t *items;
    size_t len;
    size_t cap;
} unavail_list_t;

typedef struct {
    char *name;
    char *provider;
    char *id;
    char *kind;
} cred_t;

typedef struct {
    cred_t *items;
    size_t len;
    size_t cap;
} cred_list_t;

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} str_list_t;

typedef struct {
    char *k;
    char *v;
} kv_t;

void login_list_free(login_list_t *l);
void hold_list_free(hold_list_t *h);
void unavail_list_free(unavail_list_t *u);
void cred_list_free(cred_list_t *c);
void str_list_free(str_list_t *s);
void str_list_push(str_list_t *s, const char *v);
bool str_list_has(const str_list_t *s, const char *v);

bool auth_valid_name(const char *name, char *err, size_t err_n);
bool ak_valid(const char *id);
void ak_mask(const char *key, char *out, size_t out_n);
void auth_credential_id(const char *provider, const char *name, char *out, size_t out_n);
void auth_id_for_login(const char *name, char *out, size_t out_n);

bool auth_load(login_list_t *out, char *err, size_t err_n);
bool auth_save(const login_list_t *list, char *err, size_t err_n);
bool auth_store_login(const login_t *l, char *err, size_t err_n);
bool auth_remove_login(const char *name, char *err, size_t err_n);
bool auth_is_login(const char *name, bool *out, char *err, size_t err_n);

bool auth_names(str_list_t *out, char *err, size_t err_n);
bool auth_write_names(const str_list_t *names, char *err, size_t err_n);

bool ak_read(jval_t **out, char *err, size_t err_n);
bool ak_write(const jval_t *obj, char *err, size_t err_n);
const char *ak_provider(const char *name, const jval_t *entry);
bool ak_get(const char *name, jval_t **out, char *err, size_t err_n);
bool ak_put(const char *name, jval_t *entry, char *err, size_t err_n);
bool ak_remove(const char *name, char *err, size_t err_n);
bool ak_set_named(const char *provider, const char *name, const char *key, char *err, size_t err_n);

bool auth_holds(hold_list_t *out, char *err, size_t err_n);
bool auth_limit(const char *id, const char *model, int status, const kv_t *headers, size_t hcnt, int64_t cooldown_ms, bool *limited_out, char *err, size_t err_n);
bool auth_models(unavail_list_t *out, char *err, size_t err_n);
bool auth_unavailable(const char *id, const char *model, const unavail_list_t *rows);
bool auth_model_missing(const char *id, const char *model, int status, const char *body, bool *missing_out, char *err, size_t err_n);
bool auth_forget(const char *id, char *err, size_t err_n);

int64_t auth_reading(const char *id, const char *model);
hold_t auth_hold_for(const char *id, const char *model, const hold_list_t *holds);
void auth_span(int64_t ms, char *out, size_t n);
void auth_rest(const hold_t *h, int64_t now, char *out, size_t n);
void auth_health(const char *id, const hold_list_t *holds, int64_t now, char *out, size_t n);
void auth_expiry(const login_t *l, int64_t now, char *out, size_t n);
void auth_line(const login_t *l, const hold_list_t *holds, int64_t now, sb_t *out);

bool auth_rank(const str_list_t *names, const login_list_t *logins, login_list_t *out, char *err, size_t err_n);
bool auth_credentials(cred_list_t *out, char *err, size_t err_n);
bool auth_provider_pool(const char *provider, cred_list_t *out, char *err, size_t err_n);
bool auth_credential_pick(const str_list_t *names, const cred_list_t *pool, cred_list_t *out, char *err, size_t err_n);

bool acp_name_ok(const char *name);
void acp_dir(const char *name, char *out, size_t n);
bool acp_is(const char *name, const jval_t *entry);
bool acp_email(const char *name, char *out, size_t n);
bool acp_signed(const char *name);
void acp_note(const char *name, char *out, size_t n);
bool acp_active(char *out, size_t n, bool *has_active, char *err, size_t err_n);
bool acp_free(const char *name, char *err, size_t err_n);
bool acp_add(const char *name, char *err, size_t err_n);
bool acp_activate(const char *name, char *err, size_t err_n);
bool acp_confirm(const char *name, const char *email, char *err, size_t err_n);

#endif
