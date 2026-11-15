#ifndef ASTRAG_CJSON_H
#define ASTRAG_CJSON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    J_NULL = 0,
    J_FALSE,
    J_TRUE,
    J_NUMBER,
    J_STRING,
    J_ARRAY,
    J_OBJECT
} jtype_t;

typedef struct jval {
    jtype_t type;
    char *key;
    char *str;
    double num;
    int64_t inum;
    int is_int;
    struct jval *child;
    struct jval *tail;
    struct jval *next;
    struct jval *prev;
} jval_t;

jval_t *j_parse(const char *src);
jval_t *j_parse_n(const char *src, size_t len);
void j_free(jval_t *v);
jval_t *j_dup(const jval_t *v);
int j_equal(const jval_t *a, const jval_t *b);

char *j_print(const jval_t *v, int pretty);

jval_t *j_null(void);
jval_t *j_bool(int b);
jval_t *j_int(int64_t n);
jval_t *j_num(double n);
jval_t *j_str(const char *s);
jval_t *j_arr(void);
jval_t *j_obj(void);

void j_arr_add(jval_t *arr, jval_t *item);
int j_arr_len(const jval_t *arr);
jval_t *j_arr_get(const jval_t *arr, int idx);
void j_arr_del(jval_t *arr, int idx);

jval_t *j_get(const jval_t *obj, const char *key);
void j_set(jval_t *obj, const char *key, jval_t *val);
jval_t *j_detach(jval_t *obj, const char *key);
void j_del(jval_t *obj, const char *key);

/* Convenience getters */
const char *j_get_str(const jval_t *obj, const char *key, const char *def);
int j_get_bool(const jval_t *obj, const char *key, int def);
int64_t j_get_int(const jval_t *obj, const char *key, int64_t def);
double j_get_num(const jval_t *obj, const char *key, double def);

static inline int j_is_str(const jval_t *v) { return v && v->type == J_STRING && v->str; }
static inline int j_is_bool(const jval_t *v) { return v && (v->type == J_TRUE || v->type == J_FALSE); }
static inline int j_is_num(const jval_t *v) { return v && v->type == J_NUMBER; }
static inline int j_is_arr(const jval_t *v) { return v && v->type == J_ARRAY; }
static inline int j_is_obj(const jval_t *v) { return v && v->type == J_OBJECT; }
static inline int j_bool_val(const jval_t *v) { return v && v->type == J_TRUE; }

#ifdef __cplusplus
}
#endif

#endif
