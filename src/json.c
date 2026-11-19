#define _POSIX_C_SOURCE 200809L

#include "json.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jval_t *j_alloc(jtype_t t) {
    jval_t *v = calloc(1, sizeof(jval_t));
    if (!v) abort();
    v->type = t;
    return v;
}

jval_t *j_null(void) { return j_alloc(J_NULL); }
jval_t *j_bool(bool b) { jval_t *v = j_alloc(J_BOOL); v->b = b; return v; }
jval_t *j_int(int64_t i) { jval_t *v = j_alloc(J_INT); v->i = i; return v; }
jval_t *j_num(double d) { jval_t *v = j_alloc(J_NUM); v->d = d; return v; }
jval_t *j_str(const char *s) {
    jval_t *v = j_alloc(J_STR);
    v->s = strdup(s ? s : "");
    if (!v->s) abort();
    return v;
}
jval_t *j_arr(void) { return j_alloc(J_ARR); }
jval_t *j_obj(void) { return j_alloc(J_OBJ); }

jval_t *j_clone(const jval_t *v) {
    if (!v) return j_null();
    switch (v->type) {
    case J_NULL: return j_null();
    case J_BOOL: return j_bool(v->b);
    case J_INT: return j_int(v->i);
    case J_NUM: return j_num(v->d);
    case J_STR: return j_str(v->s);
    case J_ARR: {
        jval_t *a = j_arr();
        for (size_t i = 0; i < v->arr_len; i++) j_arr_push(a, j_clone(v->arr[i]));
        return a;
    }
    case J_OBJ: {
        jval_t *o = j_obj();
        for (size_t i = 0; i < v->obj_len; i++) j_obj_set(o, v->obj[i].key, j_clone(v->obj[i].val));
        return o;
    }
    }
    return j_null();
}

void j_free(jval_t *v) {
    if (!v) return;
    if (v->type == J_STR) {
        free(v->s);
    } else if (v->type == J_ARR) {
        for (size_t i = 0; i < v->arr_len; i++) j_free(v->arr[i]);
        free(v->arr);
    } else if (v->type == J_OBJ) {
        for (size_t i = 0; i < v->obj_len; i++) {
            free(v->obj[i].key);
            j_free(v->obj[i].val);
        }
        free(v->obj);
    }
    free(v);
}

void j_arr_push(jval_t *arr, jval_t *item) {
    if (arr->arr_len == arr->arr_cap) {
        size_t ncap = arr->arr_cap ? arr->arr_cap * 2 : 8;
        arr->arr = realloc(arr->arr, ncap * sizeof(jval_t *));
        if (!arr->arr) abort();
        arr->arr_cap = ncap;
    }
    arr->arr[arr->arr_len++] = item;
}

void j_obj_set(jval_t *obj, const char *key, jval_t *val) {
    for (size_t i = 0; i < obj->obj_len; i++) {
        if (strcmp(obj->obj[i].key, key) == 0) {
            j_free(obj->obj[i].val);
            obj->obj[i].val = val;
            return;
        }
    }
    if (obj->obj_len == obj->obj_cap) {
        size_t ncap = obj->obj_cap ? obj->obj_cap * 2 : 8;
        obj->obj = realloc(obj->obj, ncap * sizeof(jkv_t));
        if (!obj->obj) abort();
        obj->obj_cap = ncap;
    }
    obj->obj[obj->obj_len].key = strdup(key);
    obj->obj[obj->obj_len].val = val;
    obj->obj_len++;
}

bool j_obj_del(jval_t *obj, const char *key) {
    for (size_t i = 0; i < obj->obj_len; i++) {
        if (strcmp(obj->obj[i].key, key) == 0) {
            free(obj->obj[i].key);
            j_free(obj->obj[i].val);
            for (size_t j = i + 1; j < obj->obj_len; j++) obj->obj[j - 1] = obj->obj[j];
            obj->obj_len--;
            return true;
        }
    }
    return false;
}

jval_t *j_obj_get(const jval_t *obj, const char *key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->obj_len; i++) {
        if (strcmp(obj->obj[i].key, key) == 0) return obj->obj[i].val;
    }
    return NULL;
}

const char *j_str_at(const jval_t *obj, const char *key) {
    jval_t *v = j_obj_get(obj, key);
    return (v && v->type == J_STR) ? v->s : "";
}

bool j_int_at(const jval_t *obj, const char *key, int64_t *out) {
    jval_t *v = j_obj_get(obj, key);
    if (!v) return false;
    if (v->type == J_INT) {
        *out = v->i;
        return true;
    }
    return false;
}

typedef struct {
    const char *p;
} jparse_t;

static void skip_ws(jparse_t *jp) {
    while (*jp->p && (*jp->p == ' ' || *jp->p == '\t' || *jp->p == '\n' || *jp->p == '\r')) jp->p++;
}

#define JSON_MAX_DEPTH 64

static jval_t *parse_val(jparse_t *jp, int depth);

static char *parse_str_raw(jparse_t *jp) {
    if (*jp->p != '"') return NULL;
    jp->p++;
    sb_t sb;
    sb_init(&sb);
    while (*jp->p && *jp->p != '"') {
        if (*jp->p == '\\') {
            jp->p++;
            char c = *jp->p;
            if (!c) { sb_free(&sb); return NULL; }
            jp->p++;
            switch (c) {
            case '"': sb_putc(&sb, '"'); break;
            case '\\': sb_putc(&sb, '\\'); break;
            case '/': sb_putc(&sb, '/'); break;
            case 'b': sb_putc(&sb, '\b'); break;
            case 'f': sb_putc(&sb, '\f'); break;
            case 'n': sb_putc(&sb, '\n'); break;
            case 'r': sb_putc(&sb, '\r'); break;
            case 't': sb_putc(&sb, '\t'); break;
            case 'u': {
                unsigned int cp = 0;
                for (int i = 0; i < 4; i++) {
                    char h = jp->p[i];
                    if (!h) { sb_free(&sb); return NULL; }
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned int)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned int)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned int)(h - 'A' + 10);
                    else { sb_free(&sb); return NULL; }
                }
                jp->p += 4;
                if (cp < 0x80) {
                    sb_putc(&sb, (char)cp);
                } else if (cp < 0x800) {
                    sb_putc(&sb, (char)(0xc0 | (cp >> 6)));
                    sb_putc(&sb, (char)(0x80 | (cp & 0x3f)));
                } else {
                    sb_putc(&sb, (char)(0xe0 | (cp >> 12)));
                    sb_putc(&sb, (char)(0x80 | ((cp >> 6) & 0x3f)));
                    sb_putc(&sb, (char)(0x80 | (cp & 0x3f)));
                }
                break;
            }
            default: sb_free(&sb); return NULL;
            }
        } else {
            sb_putc(&sb, *jp->p++);
        }
    }
    if (*jp->p != '"') { sb_free(&sb); return NULL; }
    jp->p++;
    return sb.data;
}

static jval_t *parse_val(jparse_t *jp, int depth) {
    if (depth > JSON_MAX_DEPTH) return NULL;
    skip_ws(jp);
    char c = *jp->p;
    if (!c) return NULL;
    if (c == 'n') {
        if (strncmp(jp->p, "null", 4) == 0) { jp->p += 4; return j_null(); }
        return NULL;
    }
    if (c == 't') {
        if (strncmp(jp->p, "true", 4) == 0) { jp->p += 4; return j_bool(true); }
        return NULL;
    }
    if (c == 'f') {
        if (strncmp(jp->p, "false", 5) == 0) { jp->p += 5; return j_bool(false); }
        return NULL;
    }
    if (c == '"') {
        char *s = parse_str_raw(jp);
        if (!s) return NULL;
        jval_t *v = j_alloc(J_STR);
        v->s = s;
        return v;
    }
    if (c == '[') {
        jp->p++;
        jval_t *a = j_arr();
        skip_ws(jp);
        if (*jp->p == ']') { jp->p++; return a; }
        for (;;) {
            jval_t *item = parse_val(jp, depth + 1);
            if (!item) { j_free(a); return NULL; }
            j_arr_push(a, item);
            skip_ws(jp);
            if (*jp->p == ',') { jp->p++; continue; }
            if (*jp->p == ']') { jp->p++; return a; }
            j_free(a);
            return NULL;
        }
    }
    if (c == '{') {
        jp->p++;
        jval_t *o = j_obj();
        skip_ws(jp);
        if (*jp->p == '}') { jp->p++; return o; }
        for (;;) {
            skip_ws(jp);
            char *k = parse_str_raw(jp);
            if (!k) { j_free(o); return NULL; }
            skip_ws(jp);
            if (*jp->p != ':') { free(k); j_free(o); return NULL; }
            jp->p++;
            jval_t *v = parse_val(jp, depth + 1);
            if (!v) { free(k); j_free(o); return NULL; }
            j_obj_set(o, k, v);
            free(k);
            skip_ws(jp);
            if (*jp->p == ',') { jp->p++; continue; }
            if (*jp->p == '}') { jp->p++; return o; }
            j_free(o);
            return NULL;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *start = jp->p;
        if (*jp->p == '-') jp->p++;
        if (!(*jp->p >= '0' && *jp->p <= '9')) return NULL;
        while (*jp->p >= '0' && *jp->p <= '9') jp->p++;
        bool is_flt = false;
        if (*jp->p == '.') {
            is_flt = true;
            jp->p++;
            while (*jp->p >= '0' && *jp->p <= '9') jp->p++;
        }
        if (*jp->p == 'e' || *jp->p == 'E') {
            is_flt = true;
            jp->p++;
            if (*jp->p == '+' || *jp->p == '-') jp->p++;
            while (*jp->p >= '0' && *jp->p <= '9') jp->p++;
        }
        char buf[64];
        size_t n = (size_t)(jp->p - start);
        if (n >= sizeof(buf)) return NULL;
        memcpy(buf, start, n);
        buf[n] = '\0';
        if (is_flt) return j_num(strtod(buf, NULL));
        int64_t iv = 0;
        if (!str_to_i64(buf, &iv)) return j_num(strtod(buf, NULL));
        return j_int(iv);
    }
    return NULL;
}

jval_t *j_parse(const char *src) {
    if (!src) return NULL;
    jparse_t jp = {src};
    jval_t *v = parse_val(&jp, 0);
    if (!v) return NULL;
    skip_ws(&jp);
    if (*jp.p != '\0') { j_free(v); return NULL; }
    return v;
}

static void emit_str(const char *s, sb_t *out) {
    sb_putc(out, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"') sb_puts(out, "\\\"");
        else if (c == '\\') sb_puts(out, "\\\\");
        else if (c == '\b') sb_puts(out, "\\b");
        else if (c == '\f') sb_puts(out, "\\f");
        else if (c == '\n') sb_puts(out, "\\n");
        else if (c == '\r') sb_puts(out, "\\r");
        else if (c == '\t') sb_puts(out, "\\t");
        else if (c < 0x20) sb_printf(out, "\\u%04x", c);
        else sb_putc(out, (char)c);
    }
    sb_putc(out, '"');
}

void j_emit(const jval_t *v, sb_t *out) {
    if (!v) { sb_puts(out, "null"); return; }
    switch (v->type) {
    case J_NULL: sb_puts(out, "null"); break;
    case J_BOOL: sb_puts(out, v->b ? "true" : "false"); break;
    case J_INT: sb_printf(out, "%lld", (long long)v->i); break;
    case J_NUM: sb_printf(out, "%.17g", v->d); break;
    case J_STR: emit_str(v->s, out); break;
    case J_ARR:
        sb_putc(out, '[');
        for (size_t i = 0; i < v->arr_len; i++) {
            if (i > 0) sb_putc(out, ',');
            j_emit(v->arr[i], out);
        }
        sb_putc(out, ']');
        break;
    case J_OBJ:
        sb_putc(out, '{');
        for (size_t i = 0; i < v->obj_len; i++) {
            if (i > 0) sb_putc(out, ',');
            emit_str(v->obj[i].key, out);
            sb_putc(out, ':');
            j_emit(v->obj[i].val, out);
        }
        sb_putc(out, '}');
        break;
    }
}

char *j_show(const jval_t *v) {
    sb_t sb;
    sb_init(&sb);
    j_emit(v, &sb);
    return sb.data;
}
