#ifndef JSON_H
#define JSON_H

#include "util.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    J_NULL = 0,
    J_BOOL,
    J_INT,
    J_NUM,
    J_STR,
    J_ARR,
    J_OBJ
} jtype_t;

typedef struct jval jval_t;

typedef struct {
    char *key;
    jval_t *val;
} jkv_t;

struct jval {
    jtype_t type;
    bool b;
    int64_t i;
    double d;
    char *s;
    jval_t **arr;
    size_t arr_len;
    size_t arr_cap;
    jkv_t *obj;
    size_t obj_len;
    size_t obj_cap;
};

jval_t *j_null(void);
jval_t *j_bool(bool b);
jval_t *j_int(int64_t i);
jval_t *j_num(double d);
jval_t *j_str(const char *s);
jval_t *j_arr(void);
jval_t *j_obj(void);
jval_t *j_clone(const jval_t *v);
void j_free(jval_t *v);

void j_arr_push(jval_t *arr, jval_t *item);
void j_obj_set(jval_t *obj, const char *key, jval_t *val);
bool j_obj_del(jval_t *obj, const char *key);
jval_t *j_obj_get(const jval_t *obj, const char *key);
const char *j_str_at(const jval_t *obj, const char *key);
bool j_int_at(const jval_t *obj, const char *key, int64_t *out);

jval_t *j_parse(const char *src);
void j_emit(const jval_t *v, sb_t *out);
char *j_show(const jval_t *v);

#endif
