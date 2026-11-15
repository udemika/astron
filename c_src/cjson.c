#define _GNU_SOURCE
#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0

#include "cjson.h"
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *p;
    size_t len, cap;
} jbuf_t;

static int jb_grow(jbuf_t *b, size_t need)
{
    if (b->len + need <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + need)
        nc *= 2;
    char *q = realloc(b->p, nc);
    if (!q)
        return -1;
    b->p = q;
    b->cap = nc;
    return 0;
}

static void jb_add(jbuf_t *b, const void *d, size_t n)
{
    if (!n || jb_grow(b, n + 1))
        return;
    memcpy(b->p + b->len, d, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void jb_ch(jbuf_t *b, char c)
{
    if (!jb_grow(b, 2)) {
        b->p[b->len++] = c;
        b->p[b->len] = 0;
    }
}

static void jb_str(jbuf_t *b, const char *s)
{
    jb_add(b, s, strlen(s));
}

static jval_t *j_new(jtype_t t)
{
    jval_t *v = calloc(1, sizeof *v);
    if (v)
        v->type = t;
    return v;
}

jval_t *j_null(void) { return j_new(J_NULL); }
jval_t *j_bool(int b) { return j_new(b ? J_TRUE : J_FALSE); }

jval_t *j_int(int64_t n)
{
    jval_t *v = j_new(J_NUMBER);
    if (v) {
        v->inum = n;
        v->num = (double)n;
        v->is_int = 1;
    }
    return v;
}

jval_t *j_num(double n)
{
    jval_t *v = j_new(J_NUMBER);
    if (v) {
        v->num = isfinite(n) ? n : 0.0;
        if (isfinite(n) && n >= -9e15 && n <= 9e15 && floor(n) == n) {
            v->inum = (int64_t)n;
            v->is_int = 1;
        }
    }
    return v;
}

jval_t *j_str(const char *s)
{
    jval_t *v = j_new(J_STRING);
    if (v)
        v->str = strdup(s ? s : "");
    return v;
}

jval_t *j_arr(void) { return j_new(J_ARRAY); }
jval_t *j_obj(void) { return j_new(J_OBJECT); }

void j_free(jval_t *v)
{
    while (v) {
        jval_t *nx = v->next;
        if (v->child)
            j_free(v->child);
        free(v->key);
        free(v->str);
        free(v);
        v = nx;
    }
}

static void link_child(jval_t *parent, jval_t *item)
{
    if (!parent || !item)
        return;
    item->next = NULL;
    item->prev = parent->tail;
    if (parent->tail)
        parent->tail->next = item;
    else
        parent->child = item;
    parent->tail = item;
}

void j_arr_add(jval_t *arr, jval_t *item)
{
    if (!arr || arr->type != J_ARRAY || !item) {
        j_free(item);
        return;
    }
    free(item->key);
    item->key = NULL;
    link_child(arr, item);
}

int j_arr_len(const jval_t *arr)
{
    if (!arr || arr->type != J_ARRAY)
        return 0;
    int n = 0;
    for (jval_t *c = arr->child; c; c = c->next)
        n++;
    return n;
}

jval_t *j_arr_get(const jval_t *arr, int idx)
{
    if (!arr || arr->type != J_ARRAY || idx < 0)
        return NULL;
    jval_t *c = arr->child;
    while (c && idx--)
        c = c->next;
    return c;
}

void j_arr_del(jval_t *arr, int idx)
{
    jval_t *c = j_arr_get(arr, idx);
    if (!c)
        return;
    if (c->prev)
        c->prev->next = c->next;
    else
        arr->child = c->next;
    if (c->next)
        c->next->prev = c->prev;
    else
        arr->tail = c->prev;
    c->next = c->prev = NULL;
    j_free(c);
}

jval_t *j_get(const jval_t *obj, const char *key)
{
    if (!obj || obj->type != J_OBJECT || !key)
        return NULL;
    for (jval_t *c = obj->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key))
            return c;
    return NULL;
}

jval_t *j_detach(jval_t *obj, const char *key)
{
    jval_t *c = j_get(obj, key);
    if (!c)
        return NULL;
    if (c->prev)
        c->prev->next = c->next;
    else
        obj->child = c->next;
    if (c->next)
        c->next->prev = c->prev;
    else
        obj->tail = c->prev;
    c->next = c->prev = NULL;
    return c;
}

void j_del(jval_t *obj, const char *key)
{
    j_free(j_detach(obj, key));
}

void j_set(jval_t *obj, const char *key, jval_t *val)
{
    if (!obj || obj->type != J_OBJECT || !key || !val) {
        j_free(val);
        return;
    }
    jval_t *old = j_get(obj, key);
    if (old == val)
        return;
    char *nk = strdup(key);
    free(val->key);
    val->key = nk;
    if (old) {
        val->prev = old->prev;
        val->next = old->next;
        if (old->prev)
            old->prev->next = val;
        else
            obj->child = val;
        if (old->next)
            old->next->prev = val;
        else
            obj->tail = val;
        old->next = old->prev = NULL;
        j_free(old);
    } else {
        link_child(obj, val);
    }
}

jval_t *j_dup(const jval_t *v)
{
    if (!v)
        return NULL;
    jval_t *d = j_new(v->type);
    if (!d)
        return NULL;
    if (v->key)
        d->key = strdup(v->key);
    if (v->type == J_STRING)
        d->str = strdup(v->str ? v->str : "");
    else if (v->type == J_NUMBER) {
        d->num = v->num;
        d->inum = v->inum;
        d->is_int = v->is_int;
    } else if (v->type == J_ARRAY || v->type == J_OBJECT) {
        for (jval_t *c = v->child; c; c = c->next) {
            jval_t *dc = j_dup(c);
            if (!dc) {
                j_free(d);
                return NULL;
            }
            link_child(d, dc);
        }
    }
    return d;
}

int j_equal(const jval_t *a, const jval_t *b)
{
    if (a == b)
        return 1;
    if (!a || !b || a->type != b->type)
        return 0;
    switch (a->type) {
    case J_NULL:
    case J_FALSE:
    case J_TRUE:
        return 1;
    case J_NUMBER:
        if (a->is_int && b->is_int)
            return a->inum == b->inum;
        return fabs(a->num - b->num) <= 1e-9;
    case J_STRING:
        return !strcmp(a->str ? a->str : "", b->str ? b->str : "");
    case J_ARRAY: {
        jval_t *ca = a->child, *cb = b->child;
        while (ca && cb) {
            if (!j_equal(ca, cb))
                return 0;
            ca = ca->next;
            cb = cb->next;
        }
        return !ca && !cb;
    }
    case J_OBJECT: {
        int na = 0, nb = 0;
        for (jval_t *ca = a->child; ca; ca = ca->next) {
            na++;
            jval_t *cb = j_get(b, ca->key);
            if (!cb || !j_equal(ca, cb))
                return 0;
        }
        for (jval_t *cb = b->child; cb; cb = cb->next)
            nb++;
        return na == nb;
    }
    }
    return 0;
}

const char *j_get_str(const jval_t *obj, const char *key, const char *def)
{
    jval_t *v = j_get(obj, key);
    return (v && v->type == J_STRING && v->str) ? v->str : def;
}

int j_get_bool(const jval_t *obj, const char *key, int def)
{
    jval_t *v = j_get(obj, key);
    if (!v)
        return def;
    if (v->type == J_TRUE)
        return 1;
    if (v->type == J_FALSE)
        return 0;
    if (v->type == J_STRING && v->str) {
        if (!strcasecmp(v->str, "true") || !strcmp(v->str, "1"))
            return 1;
        if (!strcasecmp(v->str, "false") || !strcmp(v->str, "0"))
            return 0;
    }
    if (v->type == J_NUMBER)
        return v->num != 0;
    return def;
}

int64_t j_get_int(const jval_t *obj, const char *key, int64_t def)
{
    jval_t *v = j_get(obj, key);
    if (!v)
        return def;
    if (v->type == J_NUMBER)
        return v->is_int ? v->inum : (int64_t)v->num;
    if (v->type == J_STRING && v->str && *v->str) {
        char *end = NULL;
        long long val = strtoll(v->str, &end, 10);
        if (end && *end == 0)
            return (int64_t)val;
    }
    return def;
}

double j_get_num(const jval_t *obj, const char *key, double def)
{
    jval_t *v = j_get(obj, key);
    if (!v)
        return def;
    if (v->type == J_NUMBER)
        return v->num;
    if (v->type == J_STRING && v->str && *v->str) {
        char *end = NULL;
        double val = strtod(v->str, &end);
        if (end && *end == 0)
            return val;
    }
    return def;
}

/* ---- Parser ---- */

typedef struct {
    const char *p, *end;
    int depth;
} jpar_t;

static void skip_ws(jpar_t *jp)
{
    while (jp->p < jp->end) {
        unsigned char c = (unsigned char)*jp->p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            jp->p++;
        else
            break;
    }
}

static int hex4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= c - '0';
        else if (c >= 'a' && c <= 'f')
            v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            v |= c - 'A' + 10;
        else
            return -1;
    }
    *out = v;
    return 0;
}

static void jb_utf8(jbuf_t *b, uint32_t cp)
{
    if (cp <= 0x7F) {
        jb_ch(b, (char)cp);
    } else if (cp <= 0x7FF) {
        jb_ch(b, (char)(0xC0 | (cp >> 6)));
        jb_ch(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        jb_ch(b, (char)(0xE0 | (cp >> 12)));
        jb_ch(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        jb_ch(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        jb_ch(b, (char)(0xF0 | (cp >> 18)));
        jb_ch(b, (char)(0x80 | ((cp >> 12) & 0x3F)));
        jb_ch(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        jb_ch(b, (char)(0x80 | (cp & 0x3F)));
    }
}

static char *parse_str_raw(jpar_t *jp)
{
    if (jp->p >= jp->end || *jp->p != '"')
        return NULL;
    jp->p++;
    jbuf_t b = {0};
    while (jp->p < jp->end) {
        unsigned char c = (unsigned char)*jp->p++;
        if (c == '"') {
            if (!b.p)
                return strdup("");
            return b.p;
        }
        if (c < 0x20) {
            free(b.p);
            return NULL;
        }
        if (c != '\\') {
            jb_ch(&b, (char)c);
            continue;
        }
        if (jp->p >= jp->end) {
            free(b.p);
            return NULL;
        }
        char esc = *jp->p++;
        switch (esc) {
        case '"':
        case '\\':
        case '/':
            jb_ch(&b, esc);
            break;
        case 'b':
            jb_ch(&b, '\b');
            break;
        case 'f':
            jb_ch(&b, '\f');
            break;
        case 'n':
            jb_ch(&b, '\n');
            break;
        case 'r':
            jb_ch(&b, '\r');
            break;
        case 't':
            jb_ch(&b, '\t');
            break;
        case 'u': {
            if (jp->p + 4 > jp->end) {
                free(b.p);
                return NULL;
            }
            uint32_t cp = 0;
            if (hex4(jp->p, &cp)) {
                free(b.p);
                return NULL;
            }
            jp->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && jp->p + 6 <= jp->end && jp->p[0] == '\\' && jp->p[1] == 'u') {
                uint32_t lo = 0;
                if (!hex4(jp->p + 2, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                    jp->p += 6;
                    cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
                }
            }
            jb_utf8(&b, cp);
            break;
        }
        default:
            free(b.p);
            return NULL;
        }
    }
    free(b.p);
    return NULL;
}

static jval_t *parse_val(jpar_t *jp);

static jval_t *parse_num(jpar_t *jp)
{
    const char *s = jp->p;
    if (*jp->p == '-')
        jp->p++;
    if (jp->p >= jp->end || !isdigit((unsigned char)*jp->p))
        return NULL;
    if (*jp->p == '0') {
        jp->p++;
    } else {
        while (jp->p < jp->end && isdigit((unsigned char)*jp->p))
            jp->p++;
    }
    int is_flt = 0;
    if (jp->p < jp->end && *jp->p == '.') {
        is_flt = 1;
        jp->p++;
        if (jp->p >= jp->end || !isdigit((unsigned char)*jp->p))
            return NULL;
        while (jp->p < jp->end && isdigit((unsigned char)*jp->p))
            jp->p++;
    }
    if (jp->p < jp->end && (*jp->p == 'e' || *jp->p == 'E')) {
        is_flt = 1;
        jp->p++;
        if (jp->p < jp->end && (*jp->p == '+' || *jp->p == '-'))
            jp->p++;
        if (jp->p >= jp->end || !isdigit((unsigned char)*jp->p))
            return NULL;
        while (jp->p < jp->end && isdigit((unsigned char)*jp->p))
            jp->p++;
    }
    size_t n = (size_t)(jp->p - s);
    char tmp[128];
    if (n >= sizeof tmp)
        return NULL;
    memcpy(tmp, s, n);
    tmp[n] = 0;
    if (!is_flt) {
        char *endp = NULL;
        long long iv = strtoll(tmp, &endp, 10);
        if (endp && *endp == 0 && (double)iv >= -9e18 && (double)iv <= 9e18)
            return j_int((int64_t)iv);
    }
    return j_num(strtod(tmp, NULL));
}

static jval_t *parse_val(jpar_t *jp)
{
    if (++jp->depth > 64) {
        jp->depth--;
        return NULL;
    }
    skip_ws(jp);
    if (jp->p >= jp->end) {
        jp->depth--;
        return NULL;
    }
    char c = *jp->p;
    jval_t *res = NULL;
    if (c == 'n' && jp->end - jp->p >= 4 && !memcmp(jp->p, "null", 4)) {
        jp->p += 4;
        res = j_null();
    } else if (c == 't' && jp->end - jp->p >= 4 && !memcmp(jp->p, "true", 4)) {
        jp->p += 4;
        res = j_bool(1);
    } else if (c == 'f' && jp->end - jp->p >= 5 && !memcmp(jp->p, "false", 5)) {
        jp->p += 5;
        res = j_bool(0);
    } else if (c == '"') {
        char *s = parse_str_raw(jp);
        if (s) {
            res = j_new(J_STRING);
            if (res)
                res->str = s;
            else
                free(s);
        }
    } else if (c == '-' || isdigit((unsigned char)c)) {
        res = parse_num(jp);
    } else if (c == '[') {
        jp->p++;
        res = j_arr();
        skip_ws(jp);
        if (jp->p < jp->end && *jp->p == ']') {
            jp->p++;
        } else {
            for (;;) {
                jval_t *item = parse_val(jp);
                if (!item) {
                    j_free(res);
                    res = NULL;
                    break;
                }
                link_child(res, item);
                skip_ws(jp);
                if (jp->p < jp->end && *jp->p == ',') {
                    jp->p++;
                    continue;
                }
                if (jp->p < jp->end && *jp->p == ']') {
                    jp->p++;
                    break;
                }
                j_free(res);
                res = NULL;
                break;
            }
        }
    } else if (c == '{') {
        jp->p++;
        res = j_obj();
        skip_ws(jp);
        if (jp->p < jp->end && *jp->p == '}') {
            jp->p++;
        } else {
            for (;;) {
                skip_ws(jp);
                char *key = parse_str_raw(jp);
                if (!key) {
                    j_free(res);
                    res = NULL;
                    break;
                }
                skip_ws(jp);
                if (jp->p >= jp->end || *jp->p != ':') {
                    free(key);
                    j_free(res);
                    res = NULL;
                    break;
                }
                jp->p++;
                jval_t *val = parse_val(jp);
                if (!val) {
                    free(key);
                    j_free(res);
                    res = NULL;
                    break;
                }
                j_set(res, key, val);
                free(key);
                skip_ws(jp);
                if (jp->p < jp->end && *jp->p == ',') {
                    jp->p++;
                    continue;
                }
                if (jp->p < jp->end && *jp->p == '}') {
                    jp->p++;
                    break;
                }
                j_free(res);
                res = NULL;
                break;
            }
        }
    }
    jp->depth--;
    return res;
}

jval_t *j_parse_n(const char *src, size_t len)
{
    if (!src)
        return NULL;
    if (len >= 3 && (uint8_t)src[0] == 0xEF && (uint8_t)src[1] == 0xBB && (uint8_t)src[2] == 0xBF) {
        src += 3;
        len -= 3;
    }
    jpar_t jp = {src, src + len, 0};
    jval_t *v = parse_val(&jp);
    if (!v)
        return NULL;
    skip_ws(&jp);
    if (jp.p != jp.end) {
        j_free(v);
        return NULL;
    }
    return v;
}

jval_t *j_parse(const char *src)
{
    return src ? j_parse_n(src, strlen(src)) : NULL;
}

/* ---- Printer ---- */

static void print_str(jbuf_t *b, const char *s)
{
    jb_ch(b, '"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; ) {
            unsigned char c = *p;
            switch (c) {
            case '"':
                jb_str(b, "\\\"");
                p++;
                break;
            case '\\':
                jb_str(b, "\\\\");
                p++;
                break;
            case '\b':
                jb_str(b, "\\b");
                p++;
                break;
            case '\f':
                jb_str(b, "\\f");
                p++;
                break;
            case '\n':
                jb_str(b, "\\n");
                p++;
                break;
            case '\r':
                jb_str(b, "\\r");
                p++;
                break;
            case '\t':
                jb_str(b, "\\t");
                p++;
                break;
            default:
                if (c < 0x20) {
                    char u[8];
                    snprintf(u, sizeof u, "\\u%04x", c);
                    jb_str(b, u);
                    p++;
                } else if (c < 0x80) {
                    jb_ch(b, (char)c);
                    p++;
                } else {
                    int ulen = 0;
                    if ((c & 0xE0) == 0xC0 && c >= 0xC2 &&
                        (p[1] & 0xC0) == 0x80) {
                        ulen = 2;
                    } else if ((c & 0xF0) == 0xE0 &&
                               (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
                               !(c == 0xE0 && p[1] < 0xA0) &&
                               !(c == 0xED && p[1] >= 0xA0)) {
                        ulen = 3;
                    } else if ((c & 0xF8) == 0xF0 && c <= 0xF4 &&
                               (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80 &&
                               !(c == 0xF0 && p[1] < 0x90) &&
                               !(c == 0xF4 && p[1] >= 0x90)) {
                        ulen = 4;
                    }
                    if (ulen > 0) {
                        jb_add(b, (const char *)p, (size_t)ulen);
                        p += ulen;
                    } else {
                        jb_str(b, "\\ufffd");
                        p++;
                    }
                }
                break;
            }
        }
    }
    jb_ch(b, '"');
}

static void print_indent(jbuf_t *b, int depth)
{
    for (int i = 0; i < depth * 2; i++)
        jb_ch(b, ' ');
}

static void print_val(jbuf_t *b, const jval_t *v, int pretty, int depth)
{
    if (!v) {
        jb_str(b, "null");
        return;
    }
    switch (v->type) {
    case J_NULL:
        jb_str(b, "null");
        break;
    case J_FALSE:
        jb_str(b, "false");
        break;
    case J_TRUE:
        jb_str(b, "true");
        break;
    case J_NUMBER: {
        char buf[64];
        if (v->is_int)
            snprintf(buf, sizeof buf, "%lld", (long long)v->inum);
        else
            snprintf(buf, sizeof buf, "%.15g", v->num);
        jb_str(b, buf);
        break;
    }
    case J_STRING:
        print_str(b, v->str);
        break;
    case J_ARRAY:
        if (!v->child) {
            jb_str(b, "[]");
            break;
        }
        jb_ch(b, '[');
        if (pretty)
            jb_ch(b, '\n');
        for (jval_t *c = v->child; c; c = c->next) {
            if (pretty)
                print_indent(b, depth + 1);
            print_val(b, c, pretty, depth + 1);
            if (c->next)
                jb_ch(b, ',');
            if (pretty)
                jb_ch(b, '\n');
        }
        if (pretty)
            print_indent(b, depth);
        jb_ch(b, ']');
        break;
    case J_OBJECT:
        if (!v->child) {
            jb_str(b, "{}");
            break;
        }
        jb_ch(b, '{');
        if (pretty)
            jb_ch(b, '\n');
        for (jval_t *c = v->child; c; c = c->next) {
            if (pretty)
                print_indent(b, depth + 1);
            print_str(b, c->key ? c->key : "");
            jb_str(b, pretty ? ": " : ":");
            print_val(b, c, pretty, depth + 1);
            if (c->next)
                jb_ch(b, ',');
            if (pretty)
                jb_ch(b, '\n');
        }
        if (pretty)
            print_indent(b, depth);
        jb_ch(b, '}');
        break;
    }
}

char *j_print(const jval_t *v, int pretty)
{
    jbuf_t b = {0};
    print_val(&b, v, pretty, 0);
    return b.p ? b.p : strdup("null");
}
