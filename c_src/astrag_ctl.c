#define _GNU_SOURCE
#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0

#include "astrag.h"
#include "www_embed.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define CLOG(...) do { fprintf(stderr, "[astrag] " __VA_ARGS__); fputc('\n', stderr); } while (0)

/* ----------------------------------------------------------- globals & state */

static char g_conf_path[1024] = "/etc/astrag/astrag.conf";
static char g_host[64] = "0.0.0.0";
static int g_port = 8000;
static time_t g_started_wall = 0;

static jval_t *g_cfg = NULL;

/* Log ring */
#define MAX_LOGS 500
typedef struct {
    char type[16];
    time_t ts;
    char text[384];
} log_entry_t;
static log_entry_t g_logs[MAX_LOGS];
static int g_log_cnt = 0;

static void add_log(const char *level, const char *fmt, ...)
{
    char msg[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (g_log_cnt >= MAX_LOGS) {
        memmove(g_logs, g_logs + 1, sizeof g_logs[0] * (MAX_LOGS - 1));
        g_log_cnt = MAX_LOGS - 1;
    }
    log_entry_t *e = &g_logs[g_log_cnt++];
    snprintf(e->type, sizeof e->type, "%s", level ? level : "info");
    e->ts = time(NULL);
    snprintf(e->text, sizeof e->text, "%s", msg);
}

/* Scans */
#define MAX_SCANS 64
typedef struct {
    int active;
    char id[24];
    char stream_id[128];
    char cluster_host[128];
} scan_t;
static scan_t g_scans[MAX_SCANS];

/* Cluster streams & cache */
#define MAX_CLUSTER_SRV 32
#define MAX_CLUSTER_STREAMS 2048
typedef struct {
    char eff_id[128];
    char orig_id[128];
    char host_port[128];
    char srv_name[128];
    int srv_idx;
    jval_t *cfg; /* owned object matching astra_clone_backend proxy_cfg */
} cluster_stream_t;

static cluster_stream_t g_cstreams[MAX_CLUSTER_STREAMS];
static int g_ncstreams = 0;

typedef struct {
    char key[128];     /* host_port or srv_name or srv_idx */
    char orig_id[128];
    char eff_id[128];
} cluster_alias_t;
static cluster_alias_t *g_calias = NULL;
static int g_ncalias = 0;

typedef struct {
    char host_port[128];
    jval_t *cfg;
} cluster_cache_t;
static cluster_cache_t g_ccache[MAX_CLUSTER_SRV];
static int g_nccache = 0;

/* Sync cycle */
typedef struct {
    int gen;
    int pending;
    jval_t *servers; /* snapshot */
    jval_t *results[MAX_CLUSTER_SRV];
} csync_ctx_t;
static int g_csync_gen = 0;
static csync_ctx_t *g_csync = NULL;
static double g_next_csync = 0.0;

/* FailedAuthLimiter */
#define AUTH_MAX_HOSTS 1024
#define AUTH_HOST_LIM 20
#define AUTH_GLOB_LIM 200
#define AUTH_WIN_S 60.0

static double g_auth_glob[AUTH_GLOB_LIM];
static int g_auth_glob_n = 0;
static struct {
    char host[64];
    double ts[AUTH_HOST_LIM];
    int n;
} g_auth_hosts[AUTH_MAX_HOSTS];
static int g_auth_nhosts = 0;

/* Cached decompressed UI buffers (allocated lazily if non-gzip client asks) */
static buf_t g_ui_index_plain = {0};
static buf_t g_ui_mod_plain = {0};
static buf_t g_ui_account_plain = {0};

/* Forward declarations */
static int apply_config(jval_t *candidate, int persist, int rebuild, char *errbuf, size_t errsz);
static void cluster_sync_start(void);
static const char *resolve_stream_id(const char *stream_id, const char *host_hint);
static channel_t *ensure_channel_started(const char *sid);
static void broadcast_ws(const char *scope, jval_t *payload);
static void broadcast_cluster_ws(const char *host_port, const char *scope, jval_t *payload);

/* ----------------------------------------------------------- utils & HTTP */

static int hex_val(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void url_decode_inplace(char *s)
{
    char *o = s;
    for (; *s; s++) {
        int h, l;
        if (*s == '%' && (h = hex_val(s[1])) >= 0 && (l = hex_val(s[2])) >= 0) {
            *o++ = (char)(h * 16 + l);
            s += 2;
        } else {
            *o++ = *s;
        }
    }
    *o = 0;
}

static void xml_escape_buf(buf_t *b, const char *s)
{
    if (!s)
        return;
    for (; *s; s++) {
        switch (*s) {
        case '&': buf_str(b, "&amp;"); break;
        case '<': buf_str(b, "&lt;"); break;
        case '>': buf_str(b, "&gt;"); break;
        case '"': buf_str(b, "&quot;"); break;
        default: buf_add(b, s, 1); break;
        }
    }
}

static void gen_uuid_hex(char *out, size_t outsz, size_t bytes)
{
    uint8_t rb[32];
    if (bytes > sizeof rb)
        bytes = sizeof rb;
    RAND_bytes(rb, (int)bytes);
    size_t pos = 0;
    for (size_t i = 0; i < bytes && pos + 2 < outsz; i++) {
        snprintf(out + pos, outsz - pos, "%02x", rb[i]);
        pos += 2;
    }
    out[pos] = 0;
}

static int b64_encode(const uint8_t *in, size_t len, char *out, size_t outsz)
{
    if (outsz < 4 * ((len + 2) / 3) + 1)
        return -1;
    int r = EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    out[r] = 0;
    return r;
}

static int b64_decode(const char *in, size_t len, char *out, size_t outsz)
{
    while (len > 0 && (in[len - 1] == ' ' || in[len - 1] == '\r' || in[len - 1] == '\n'))
        len--;
    if (!len || (len % 4) != 0)
        return -1;
    size_t pad = 0;
    if (in[len - 1] == '=')
        pad++;
    if (len >= 2 && in[len - 2] == '=')
        pad++;
    size_t maxd = (len / 4) * 3;
    if (maxd + 1 > outsz)
        return -1;
    int d = EVP_DecodeBlock((unsigned char *)out, (const unsigned char *)in, (int)len);
    if (d < 0)
        return -1;
    d -= (int)pad;
    if (d < 0)
        return -1;
    out[d] = 0;
    return d;
}

/* Parsed request view */
typedef struct {
    char method[16];
    char raw_target[4096];
    char path[2048];
    char query[2048];
    char host[256];
    char authorization[1024];
    char cookie[1024];
    char origin[512];
    char user_agent[256];
    char x_real_ip[128];
    char x_fwd_for[256];
    char x_cluster_target[256];
    char x_cluster_auth[512];
    char x_ui_auth[64];
    char sec_ws_key[128];
    char upgrade[64];
    int sec_fetch_mode;
    int accept_gzip;
    const uint8_t *body;
    size_t body_len;
} req_t;

static void parse_req(front_t *fr, size_t head_len, size_t body_len, req_t *r)
{
    memset(r, 0, sizeof *r);
    r->body = fr->in.p + head_len;
    r->body_len = body_len;
    char *hdr = malloc(head_len + 1);
    if (!hdr)
        return;
    memcpy(hdr, fr->in.p, head_len);
    hdr[head_len] = 0;

    char *eol = strchr(hdr, '\n');
    if (eol)
        *eol = 0;
    size_t l0 = strlen(hdr);
    if (l0 && hdr[l0 - 1] == '\r')
        hdr[--l0] = 0;
    char *sp1 = strchr(hdr, ' ');
    if (sp1) {
        size_t ml = (size_t)(sp1 - hdr);
        if (ml >= sizeof r->method)
            ml = sizeof r->method - 1;
        memcpy(r->method, hdr, ml);
        char *sp2 = strchr(sp1 + 1, ' ');
        size_t tl = sp2 ? (size_t)(sp2 - (sp1 + 1)) : strlen(sp1 + 1);
        if (tl >= sizeof r->raw_target)
            tl = sizeof r->raw_target - 1;
        memcpy(r->raw_target, sp1 + 1, tl);
    }
    const char *q = strchr(r->raw_target, '?');
    if (q) {
        size_t pl = (size_t)(q - r->raw_target);
        if (pl >= sizeof r->path)
            pl = sizeof r->path - 1;
        memcpy(r->path, r->raw_target, pl);
        snprintf(r->query, sizeof r->query, "%s", q + 1);
    } else {
        snprintf(r->path, sizeof r->path, "%.*s", (int)(sizeof r->path - 1), r->raw_target);
    }
    url_decode_inplace(r->path);

    char *line = eol ? eol + 1 : NULL;
    while (line && *line) {
        char *nx = strchr(line, '\n');
        if (nx)
            *nx = 0;
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\r')
            line[--ll] = 0;
        if (!ll)
            break;
        char *col = strchr(line, ':');
        if (col) {
            *col = 0;
            char *v = col + 1;
            while (*v == ' ' || *v == '\t')
                v++;
            if (!strcasecmp(line, "host"))
                snprintf(r->host, sizeof r->host, "%s", v);
            else if (!strcasecmp(line, "authorization"))
                snprintf(r->authorization, sizeof r->authorization, "%s", v);
            else if (!strcasecmp(line, "cookie"))
                snprintf(r->cookie, sizeof r->cookie, "%s", v);
            else if (!strcasecmp(line, "origin"))
                snprintf(r->origin, sizeof r->origin, "%s", v);
            else if (!strcasecmp(line, "user-agent"))
                snprintf(r->user_agent, sizeof r->user_agent, "%s", v);
            else if (!strcasecmp(line, "x-real-ip"))
                snprintf(r->x_real_ip, sizeof r->x_real_ip, "%s", v);
            else if (!strcasecmp(line, "x-forwarded-for"))
                snprintf(r->x_fwd_for, sizeof r->x_fwd_for, "%s", v);
            else if (!strcasecmp(line, "x-cluster-target"))
                snprintf(r->x_cluster_target, sizeof r->x_cluster_target, "%s", v);
            else if (!strcasecmp(line, "x-cluster-auth"))
                snprintf(r->x_cluster_auth, sizeof r->x_cluster_auth, "%s", v);
            else if (!strcasecmp(line, "x-astra-ui-auth"))
                snprintf(r->x_ui_auth, sizeof r->x_ui_auth, "%s", v);
            else if (!strcasecmp(line, "sec-websocket-key"))
                snprintf(r->sec_ws_key, sizeof r->sec_ws_key, "%s", v);
            else if (!strcasecmp(line, "upgrade"))
                snprintf(r->upgrade, sizeof r->upgrade, "%s", v);
            else if (!strcasecmp(line, "sec-fetch-mode"))
                r->sec_fetch_mode = 1;
            else if (!strcasecmp(line, "accept-encoding") && strcasestr(v, "gzip"))
                r->accept_gzip = 1;
        }
        line = nx ? nx + 1 : NULL;
    }
    free(hdr);
}

static int query_has(const char *query, const char *key)
{
    if (!query || !*query)
        return 0;
    size_t kl = strlen(key);
    const char *p = query;
    while (*p) {
        size_t n = strcspn(p, "&");
        size_t kpart = strcspn(p, "=&");
        if (kpart == kl && !strncmp(p, key, kl))
            return 1;
        p += n;
        if (*p == '&')
            p++;
    }
    return 0;
}

static int query_get(const char *query, const char *key, char *out, size_t outsz)
{
    out[0] = 0;
    if (!query || !*query)
        return 0;
    size_t kl = strlen(key);
    const char *p = query;
    while (*p) {
        size_t n = strcspn(p, "&");
        const char *eq = memchr(p, '=', n);
        size_t kpart = eq ? (size_t)(eq - p) : n;
        if (kpart == kl && !strncmp(p, key, kl)) {
            if (eq) {
                size_t vl = n - kpart - 1;
                if (vl >= outsz)
                    vl = outsz - 1;
                memcpy(out, eq + 1, vl);
                out[vl] = 0;
                url_decode_inplace(out);
            }
            return 1;
        }
        p += n;
        if (*p == '&')
            p++;
    }
    return 0;
}

static void send_json(front_t *fr, int code, const char *reason, const jval_t *v, const char *extra_hdrs)
{
    char *s = j_print(v, 0);
    if (!s) {
        front_error(fr, 500, "JSON serialize failed");
        return;
    }
    front_respond(fr, code, reason ? reason : "OK", "application/json", extra_hdrs, s, strlen(s), NULL, 0);
    free(s);
}

static void send_detail(front_t *fr, int code, const char *reason, const char *detail, const char *extra_hdrs)
{
    jval_t *o = j_obj();
    j_set(o, "detail", j_str(detail ? detail : reason));
    send_json(fr, code, reason, o, extra_hdrs);
    j_free(o);
}

/* ----------------------------------------------------------- security */

static int valid_login(const char *s)
{
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 1 || n > 64)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == '@' || c == '-'))
            return 0;
    }
    return 1;
}

static int valid_password(const char *s)
{
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 12 || n > 256)
        return 0;
    int has_a = 0, has_d = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c >= 0x80)
            has_a = 1;
        if (c >= '0' && c <= '9')
            has_d = 1;
    }
    return has_a && has_d;
}

static int hex_decode(const char *hex, uint8_t *out, size_t nbytes)
{
    if (!hex || strlen(hex) != nbytes * 2)
        return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int h = hex_val(hex[i * 2]);
        int l = hex_val(hex[i * 2 + 1]);
        if (h < 0 || l < 0)
            return -1;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return 0;
}

static int hash_password(const char *pw, char *out, size_t outsz)
{
    if (!pw || outsz < 128)
        return -1;
    uint8_t salt[16], digest[32];
    if (RAND_bytes(salt, sizeof salt) != 1)
        return -1;
    const int rounds = 600000;
    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, sizeof salt, rounds, EVP_sha256(), sizeof digest, digest) != 1)
        return -1;
    char sh[33], dh[65];
    for (int i = 0; i < 16; i++)
        sprintf(sh + i * 2, "%02x", salt[i]);
    sh[32] = 0;
    for (int i = 0; i < 32; i++)
        sprintf(dh + i * 2, "%02x", digest[i]);
    dh[64] = 0;
    snprintf(out, outsz, "pbkdf2_sha256$%d$%s$%s", rounds, sh, dh);
    return 0;
}

static int verify_password(const char *pw, const char *stored)
{
    if (!pw || !stored || !*stored || strlen(pw) > 256)
        return 0;
    const char *pref = "pbkdf2_sha256$";
    if (strncmp(stored, pref, strlen(pref)) != 0) {
        size_t lp = strlen(pw), ls = strlen(stored);
        if (lp != ls)
            return 0;
        return CRYPTO_memcmp(pw, stored, lp) == 0;
    }
    char copy[256];
    snprintf(copy, sizeof copy, "%s", stored + strlen(pref));
    char *d1 = strchr(copy, '$');
    if (!d1)
        return 0;
    *d1++ = 0;
    char *d2 = strchr(d1, '$');
    if (!d2 || strchr(d2 + 1, '$'))
        return 0;
    *d2++ = 0;
    long rounds = strtol(copy, NULL, 10);
    if (rounds < 100000 || rounds > 2000000)
        return 0;
    uint8_t salt[16], digest[32], actual[32];
    if (hex_decode(d1, salt, 16) < 0 || hex_decode(d2, digest, 32) < 0)
        return 0;
    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, 16, (int)rounds, EVP_sha256(), 32, actual) != 1)
        return 0;
    return CRYPTO_memcmp(actual, digest, 32) == 0;
}

static void auth_limiter_prune(void)
{
    double cutoff = g_now - AUTH_WIN_S;
    int keep = 0;
    for (int i = 0; i < g_auth_glob_n; i++)
        if (g_auth_glob[i] > cutoff)
            g_auth_glob[keep++] = g_auth_glob[i];
    g_auth_glob_n = keep;

    int hk = 0;
    for (int i = 0; i < g_auth_nhosts; i++) {
        int tn = 0;
        for (int j = 0; j < g_auth_hosts[i].n; j++)
            if (g_auth_hosts[i].ts[j] > cutoff)
                g_auth_hosts[i].ts[tn++] = g_auth_hosts[i].ts[j];
        if (tn > 0) {
            g_auth_hosts[i].n = tn;
            if (hk != i)
                g_auth_hosts[hk] = g_auth_hosts[i];
            hk++;
        }
    }
    g_auth_nhosts = hk;
}

static int auth_limiter_blocked(const char *host)
{
    auth_limiter_prune();
    if (g_auth_glob_n >= AUTH_GLOB_LIM)
        return 1;
    if (!host)
        return 0;
    for (int i = 0; i < g_auth_nhosts; i++)
        if (!strcmp(g_auth_hosts[i].host, host))
            return g_auth_hosts[i].n >= AUTH_HOST_LIM;
    return 0;
}

static void auth_limiter_failed(const char *host)
{
    auth_limiter_prune();
    if (g_auth_glob_n < AUTH_GLOB_LIM)
        g_auth_glob[g_auth_glob_n++] = g_now;
    if (!host)
        return;
    for (int i = 0; i < g_auth_nhosts; i++) {
        if (!strcmp(g_auth_hosts[i].host, host)) {
            if (g_auth_hosts[i].n < AUTH_HOST_LIM)
                g_auth_hosts[i].ts[g_auth_hosts[i].n++] = g_now;
            return;
        }
    }
    if (g_auth_nhosts < AUTH_MAX_HOSTS) {
        int i = g_auth_nhosts++;
        snprintf(g_auth_hosts[i].host, sizeof g_auth_hosts[i].host, "%s", host);
        g_auth_hosts[i].ts[0] = g_now;
        g_auth_hosts[i].n = 1;
    }
}

static int ip_matches(const char *host, const jval_t *rules)
{
    if (!host || !*host || !j_is_arr(rules))
        return 0;
    uint8_t addr[16];
    int fam = 0;
    if (inet_pton(AF_INET, host, addr) == 1)
        fam = AF_INET;
    else if (inet_pton(AF_INET6, host, addr) == 1)
        fam = AF_INET6;

    for (jval_t *item = rules->child; item; item = item->next) {
        if (!j_is_str(item))
            continue;
        char rule[128];
        snprintf(rule, sizeof rule, "%s", item->str);
        char *p = rule;
        while (*p == ' ') p++;
        size_t rl = strlen(p);
        while (rl > 0 && p[rl - 1] == ' ') p[--rl] = 0;
        if (!*p)
            continue;
        char *sl = strchr(p, '/');
        if (!sl) {
            if (!strcmp(host, p))
                return 1;
            if (fam) {
                uint8_t ra[16];
                if (inet_pton(fam, p, ra) == 1 &&
                    memcmp(addr, ra, fam == AF_INET ? 4 : 16) == 0)
                    return 1;
            }
        } else if (fam) {
            *sl++ = 0;
            int prefix = atoi(sl);
            int maxb = fam == AF_INET ? 32 : 128;
            uint8_t ra[16];
            if (prefix >= 0 && prefix <= maxb && inet_pton(fam, p, ra) == 1) {
                int full = prefix / 8;
                int rem = prefix % 8;
                if (memcmp(addr, ra, (size_t)full) == 0) {
                    if (rem == 0)
                        return 1;
                    uint8_t mask = (uint8_t)(0xFF << (8 - rem));
                    if ((addr[full] & mask) == (ra[full] & mask))
                        return 1;
                }
            }
        }
    }
    return 0;
}

typedef struct {
    int ok;
    int status;
    char login[96];
    int admin;
    char detail[128];
} auth_res_t;

static auth_res_t check_identity(const char *creds, const char *host, int req_creds, int rate_limit)
{
    auth_res_t res = {0};
    const jval_t *auth = j_get(g_cfg, "auth");
    int auth_en = j_get_bool(auth, "enable", 0);

    if (rate_limit && (auth_en || creds != NULL) && auth_limiter_blocked(host)) {
        res.status = 429;
        snprintf(res.detail, sizeof res.detail, "Too many failed authentication attempts");
        return res;
    }
    if (!auth_en && !req_creds && !creds) {
        res.ok = 1;
        res.admin = 1;
        return res;
    }
    const char *colon = creds ? strchr(creds, ':') : NULL;
    if (!colon) {
        if (rate_limit && (auth_en || creds != NULL))
            auth_limiter_failed(host);
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "Forbidden");
        return res;
    }
    size_t ll = (size_t)(colon - creds);
    if (ll >= sizeof res.login)
        ll = sizeof res.login - 1;
    memcpy(res.login, creds, ll);
    res.login[ll] = 0;
    const char *pass = colon + 1;

    const jval_t *users = j_get(g_cfg, "users");
    const jval_t *u = j_get(users, res.login);
    if (!u || j_get_bool(u, "enable", 1) == 0) {
        if (rate_limit && (auth_en || creds != NULL))
            auth_limiter_failed(host);
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "Forbidden");
        return res;
    }
    const char *expected = j_get_str(u, "password", NULL);
    if (!expected || !*expected)
        expected = j_get_str(u, "token", NULL);
    if (!verify_password(pass, expected)) {
        if (rate_limit && (auth_en || creds != NULL))
            auth_limiter_failed(host);
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "Forbidden");
        return res;
    }
    const jval_t *exp = j_get(u, "expire");
    if (j_is_num(exp) && exp->num > 0 && (double)time(NULL) > exp->num) {
        if (rate_limit && (auth_en || creds != NULL))
            auth_limiter_failed(host);
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "Forbidden");
        return res;
    }
    const char *role = j_get_str(u, "role", "");
    const jval_t *utype = j_get(u, "type");
    int is_adm = !strcmp(role, "admin") ||
                 (j_is_num(utype) && (int)utype->inum == 1) ||
                 (j_is_str(utype) && !strcmp(utype->str, "1"));
    res.ok = 1;
    res.admin = is_adm;
    return res;
}

static int extract_basic(const char *hdr, char *out, size_t outsz)
{
    if (!hdr || strncasecmp(hdr, "Basic ", 6) != 0)
        return 0;
    const char *p = hdr + 6;
    while (*p == ' ') p++;
    int n = b64_decode(p, strlen(p), out, outsz);
    return n >= 0 ? 1 : 0;
}

static int extract_cookie_auth(const char *cookie, char *out, size_t outsz)
{
    out[0] = 0;
    if (!cookie || !*cookie)
        return 0;
    const char *p = cookie;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ';')
            p++;
        if (!*p)
            break;
        size_t n = strcspn(p, ";");
        const char *eq = memchr(p, '=', n);
        if (eq && (size_t)(eq - p) == 4 && !strncmp(p, "auth", 4)) {
            size_t vl = n - 5;
            if (vl >= outsz)
                vl = outsz - 1;
            memcpy(out, eq + 1, vl);
            out[vl] = 0;
            url_decode_inplace(out);
            return out[0] ? 1 : 0;
        }
        p += n;
    }
    return 0;
}

static auth_res_t require_auth(front_t *fr, const req_t *r)
{
    char creds[512];
    int has_creds = extract_basic(r->authorization, creds, sizeof creds);
    if (!has_creds)
        has_creds = extract_cookie_auth(r->cookie, creds, sizeof creds);
    int is_browser = (strcasestr(r->user_agent, "mozilla/") != NULL) || r->sec_fetch_mode;
    int ui_req = !strcmp(r->x_ui_auth, "required") || is_browser;
    if (ui_req && !has_creds) {
        auth_res_t res = {0};
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "Forbidden");
        return res;
    }
    return check_identity(has_creds ? creds : NULL, fr->ip, ui_req, 1);
}

static auth_res_t require_media_auth(front_t *fr, const req_t *r)
{
    const jval_t *auth = j_get(g_cfg, "auth");
    int auth_en = j_get_bool(auth, "enable", 0);
    char host[128];
    snprintf(host, sizeof host, "%s", fr->ip);
    if (j_get_bool(auth, "x_real_ip", 0)) {
        if (r->x_real_ip[0])
            snprintf(host, sizeof host, "%s", r->x_real_ip);
        else if (r->x_fwd_for[0]) {
            size_t cl = strcspn(r->x_fwd_for, ",");
            snprintf(host, sizeof host, "%.*s", (int)cl, r->x_fwd_for);
        }
    }
    if (ip_matches(host, j_get(auth, "http_ip_deny"))) {
        auth_res_t res = {0};
        res.status = 403;
        snprintf(res.detail, sizeof res.detail, "IP address denied");
        return res;
    }
    char token[512] = "";
    if (!query_get(r->query, "token", token, sizeof token))
        query_get(r->query, "auth", token, sizeof token);
    if (token[0]) {
        const jval_t *tdeny = j_get(auth, "http_token_deny");
        if (j_is_arr(tdeny)) {
            for (jval_t *it = tdeny->child; it; it = it->next) {
                if (j_is_str(it) && !strcmp(it->str, token)) {
                    auth_res_t res = {0};
                    res.status = 403;
                    snprintf(res.detail, sizeof res.detail, "Token denied");
                    return res;
                }
            }
        }
        if (strchr(token, ':')) {
            auth_res_t res = check_identity(token, host, 1, 1);
            if (res.ok || auth_en)
                return res;
        }
        const jval_t *users = j_get(g_cfg, "users");
        if (j_is_obj(users)) {
            for (jval_t *u = users->child; u; u = u->next) {
                if (!j_is_obj(u) || !u->key || j_get_bool(u, "enable", 1) == 0)
                    continue;
                const char *utok = j_get_str(u, "token", NULL);
                const char *upw = j_get_str(u, "password", NULL);
                if ((utok && !strcmp(utok, token)) || (upw && verify_password(token, upw))) {
                    auth_res_t res = {0};
                    res.ok = 1;
                    snprintf(res.login, sizeof res.login, "%s", u->key);
                    const char *role = j_get_str(u, "role", "");
                    const jval_t *utype = j_get(u, "type");
                    res.admin = !strcmp(role, "admin") || (j_is_num(utype) && utype->inum == 1);
                    return res;
                }
            }
        }
        if (auth_en) {
            auth_res_t res = {0};
            res.status = 403;
            snprintf(res.detail, sizeof res.detail, "Forbidden");
            return res;
        }
    }
    if (!auth_en) {
        char creds[512];
        if (extract_basic(r->authorization, creds, sizeof creds)) {
            auth_res_t res = check_identity(creds, host, 1, 0);
            if (res.ok)
                return res;
        }
        auth_res_t res = {0};
        res.ok = 1;
        return res;
    }
    if (ip_matches(host, j_get(auth, "http_ip_allow"))) {
        auth_res_t res = {0};
        res.ok = 1;
        return res;
    }
    return require_auth(fr, r);
}

/* ----------------------------------------------------------- config & disk */

static jval_t *default_admin_obj(void)
{
    jval_t *u = j_obj();
    j_set(u, "type", j_int(1));
    j_set(u, "role", j_str("admin"));
    j_set(u, "enable", j_bool(1));
    j_set(u, "password", j_str("admin"));
    j_set(u, "created", j_int((int64_t)time(NULL)));
    return u;
}

static jval_t *default_cfg_obj(int port, const char *host)
{
    jval_t *c = j_obj();
    j_set(c, "port", j_int(port));
    j_set(c, "host", j_str(host && *host ? host : "0.0.0.0"));
    j_set(c, "gid", j_int(466560));
    jval_t *au = j_obj();
    j_set(au, "enable", j_bool(0));
    j_set(c, "auth", au);
    jval_t *us = j_obj();
    j_set(us, "admin", default_admin_obj());
    j_set(c, "users", us);
    j_set(c, "make_stream", j_arr());
    j_set(c, "categories", j_arr());
    j_set(c, "servers", j_arr());
    j_set(c, "softcam", j_arr());
    j_set(c, "cas", j_arr());
    j_set(c, "dvb_tune", j_arr());
    j_set(c, "settings", j_obj());
    j_set(c, "hls", j_obj());
    return c;
}

static int read_file_str(const char *path, char **out, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0 || sz > 64 * 1024 * 1024) {
        fclose(fp);
        return -1;
    }
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t n = sz > 0 ? fread(buf, 1, (size_t)sz, fp) : 0;
    fclose(fp);
    buf[n] = 0;
    /* Strip UTF-8 BOM */
    if (n >= 3 && (uint8_t)buf[0] == 0xEF && (uint8_t)buf[1] == 0xBB && (uint8_t)buf[2] == 0xBF) {
        memmove(buf, buf + 3, n - 2);
        n -= 3;
    }
    *out = buf;
    if (out_len)
        *out_len = n;
    return 0;
}

static int atomic_write_file(const char *path, const char *data, size_t len, mode_t mode)
{
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *d = dirname(dir);
    /* mkdir_p single level */
    mkdir(d, 0750);

    char tmp[1088];
    snprintf(tmp, sizeof tmp, "%s/.astra-XXXXXX", d);
    int fd = mkstemp(tmp);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(fd, data + off, len - off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                close(fd);
                unlink(tmp);
                return -1;
            }
            off += (size_t)w;
        }
        fsync(fd);
        fchmod(fd, mode);
        close(fd);
        if (rename(tmp, path) == 0)
            return 0;
        unlink(tmp);
    }
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;
    fwrite(data, 1, len, fp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return 0;
}

static jval_t *format_config_payload(const jval_t *cfg)
{
    static const char *keys[] = {
        "port", "host", "gid", "auth", "users", "make_stream",
        "categories", "servers", "softcam", "cas", "dvb_tune", "settings", "hls"
    };
    jval_t *ord = j_obj();
    int p = (int)j_get_int(cfg, "port", j_get_int(cfg, "control_port", g_port));
    const char *h = j_get_str(cfg, "host", g_host);
    j_set(ord, "port", j_int(p));
    j_set(ord, "host", j_str(h && *h ? h : g_host));
    for (size_t i = 2; i < sizeof keys / sizeof keys[0]; i++) {
        const jval_t *v = j_get(cfg, keys[i]);
        if (v)
            j_set(ord, keys[i], j_dup(v));
    }
    for (jval_t *c = cfg->child; c; c = c->next) {
        if (!c->key || !strcmp(c->key, "control_port") || j_get(ord, c->key))
            continue;
        j_set(ord, c->key, j_dup(c));
    }
    size_t pl = strlen(g_conf_path);
    if (pl >= 5 && !strcmp(g_conf_path + pl - 5, ".conf"))
        return ord;
    jval_t *wrap = j_obj();
    j_set(wrap, "config", ord);
    return wrap;
}

static int atomic_save(const jval_t *cfg)
{
    jval_t *payload = format_config_payload(cfg);
    char *txt = j_print(payload, 1);
    j_free(payload);
    if (!txt)
        return -1;
    size_t tl = strlen(txt);
    char *out = malloc(tl + 2);
    if (!out) {
        free(txt);
        return -1;
    }
    memcpy(out, txt, tl);
    out[tl] = '\n';
    out[tl + 1] = 0;
    free(txt);
    int r = atomic_write_file(g_conf_path, out, tl + 1, 0640);
    free(out);
    return r;
}

/* URL validator (returns malloc'd normalized string or NULL on error) */
static char *validate_url(const char *raw, int output, char *err, size_t errsz)
{
    if (!raw) {
        snprintf(err, errsz, "URL must be a nonempty string");
        return NULL;
    }
    while (*raw && isspace((unsigned char)*raw))
        raw++;
    size_t n = strlen(raw);
    while (n > 0 && isspace((unsigned char)raw[n - 1]))
        n--;
    if (n == 0 || n > 4000) {
        snprintf(err, errsz, "URL must be a nonempty string without whitespace");
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        if (isspace((unsigned char)raw[i])) {
            snprintf(err, errsz, "URL must be a nonempty string without whitespace");
            return NULL;
        }
    }
    char buf[4096];
    if (output && (!strncasecmp(raw, "http://:", 8) || !strncasecmp(raw, "https://:", 9))) {
        int is_tls = !strncasecmp(raw, "https://:", 9);
        snprintf(buf, sizeof buf, "%s://0.0.0.0:%.*s", is_tls ? "https" : "http",
                 (int)(n - (is_tls ? 9 : 8)), raw + (is_tls ? 9 : 8));
    } else {
        snprintf(buf, sizeof buf, "%.*s", (int)n, raw);
    }

    char clean[4096];
    snprintf(clean, sizeof clean, "%s", buf);
    char *hash = strchr(clean, '#');
    if (hash)
        *hash = 0;

    char *sc_end = strstr(clean, "://");
    if (!sc_end) {
        snprintf(err, errsz, output ? "unsupported output transport" : "unsupported input transport");
        return NULL;
    }
    *sc_end = 0;
    int is_udp = !strcasecmp(clean, "udp");
    int is_rtp = !strcasecmp(clean, "rtp");
    int is_http = !strcasecmp(clean, "http") || !strcasecmp(clean, "https");
    if (output ? !(is_http || is_udp) : !(is_http || is_udp || is_rtp)) {
        snprintf(err, errsz, output ? "unsupported output transport" : "unsupported input transport");
        return NULL;
    }
    char *auth_start = sc_end + 3;
    char *auth_end = auth_start + strcspn(auth_start, "/?");
    char *at = memrchr(auth_start, '@', (size_t)(auth_end - auth_start));
    char *hp = at ? at + 1 : auth_start;
    if (hp >= auth_end) {
        snprintf(err, errsz, "URL requires a host");
        return NULL;
    }
    char *colon = memchr(hp, ':', (size_t)(auth_end - hp));
    if (colon == hp) {
        snprintf(err, errsz, "URL requires a host");
        return NULL;
    }
    int port = -1;
    if (colon) {
        char *ep = NULL;
        long pv = strtol(colon + 1, &ep, 10);
        if (ep == colon + 1 || pv < 1 || pv > 65535) {
            snprintf(err, errsz, "invalid port");
            return NULL;
        }
        port = (int)pv;
    } else if (is_udp || is_rtp) {
        snprintf(err, errsz, "UDP/RTP URL requires a port");
        return NULL;
    }
    (void)port;
    return strdup(buf);
}

static int validate_stream_entry(jval_t *s, char *err, size_t errsz)
{
    if (!j_is_obj(s)) {
        snprintf(err, errsz, "each stream entry must be an object");
        return -1;
    }
    const jval_t *vid = j_get(s, "id");
    const jval_t *vname = j_get(s, "name");
    const jval_t *vtype = j_get(s, "type");
    const jval_t *ven = j_get(s, "enable");
    if ((vid && !j_is_str(vid)) || (vname && !j_is_str(vname)) || (vtype && !j_is_str(vtype))) {
        snprintf(err, errsz, "stream id, name, and type must be strings");
        return -1;
    }
    if (ven && !j_is_bool(ven)) {
        snprintf(err, errsz, "stream enable must be a boolean");
        return -1;
    }
    if (!vid) j_set(s, "id", j_str(""));
    if (!vname) j_set(s, "name", j_str(""));
    if (!vtype) j_set(s, "type", j_str("spts"));
    if (!ven) j_set(s, "enable", j_bool(1));

    const char *lkeys[4] = {"input", "output", "_input", "_output"};
    int is_out[4] = {0, 1, 0, 1};
    for (int li = 0; li < 4; li++) {
        const jval_t *arr = j_get(s, lkeys[li]);
        if (!arr) {
            if (li < 2) {
                j_set(s, lkeys[li], j_arr());
            }
            continue;
        }
        if (!j_is_arr(arr)) {
            if (li < 2) {
                snprintf(err, errsz, "stream input and output must be lists");
                return -1;
            }
            continue;
        }
        jval_t *cleaned = j_arr();
        for (jval_t *it = arr->child; it; it = it->next) {
            if (j_is_str(it)) {
                const char *p = it->str;
                while (*p && isspace((unsigned char)*p)) p++;
                if (!*p)
                    continue;
                char *norm = validate_url(it->str, is_out[li], err, errsz);
                if (!norm) {
                    j_free(cleaned);
                    return -1;
                }
                j_arr_add(cleaned, j_str(norm));
                free(norm);
            } else {
                char *norm = validate_url(NULL, is_out[li], err, errsz);
                j_free(cleaned);
                free(norm);
                return -1;
            }
        }
        if (li >= 2 && j_arr_len(cleaned) == 0) {
            j_free(cleaned);
            j_del(s, lkeys[li]);
        } else {
            j_set(s, lkeys[li], cleaned);
        }
    }
    return 0;
}

static jval_t *validate_config(const jval_t *raw, char *err, size_t errsz)
{
    if (!j_is_obj(raw)) {
        snprintf(err, errsz, "config must be an object");
        return NULL;
    }
    jval_t *res = default_cfg_obj(g_port, g_host);
    for (jval_t *c = raw->child; c; c = c->next) {
        if (c->key)
            j_set(res, c->key, j_dup(c));
    }
    const jval_t *ms = j_get(res, "make_stream");
    if (!j_is_arr(ms)) {
        snprintf(err, errsz, "make_stream must be a list");
        j_free(res);
        return NULL;
    }
    for (jval_t *s = ms->child; s; s = s->next) {
        if (validate_stream_entry(s, err, errsz) < 0) {
            j_free(res);
            return NULL;
        }
        const char *sid = j_get_str(s, "id", "");
        if (!*sid) {
            snprintf(err, errsz, "stream IDs must be nonempty and unique");
            j_free(res);
            return NULL;
        }
        for (jval_t *prev = ms->child; prev != s; prev = prev->next) {
            if (!strcmp(j_get_str(prev, "id", ""), sid)) {
                snprintf(err, errsz, "stream IDs must be nonempty and unique");
                j_free(res);
                return NULL;
            }
        }
    }
    static const char *okeys[] = {"settings", "auth", "users", "hls"};
    for (size_t i = 0; i < 4; i++) {
        if (!j_is_obj(j_get(res, okeys[i]))) {
            snprintf(err, errsz, "%s must be an object", okeys[i]);
            j_free(res);
            return NULL;
        }
    }
    static const char *akeys[] = {"categories", "servers", "softcam", "cas", "dvb_tune"};
    for (size_t i = 0; i < 5; i++) {
        const jval_t *a = j_get(res, akeys[i]);
        if (!j_is_arr(a)) {
            snprintf(err, errsz, "%s must be a list of objects", akeys[i]);
            j_free(res);
            return NULL;
        }
        for (jval_t *el = a->child; el; el = el->next) {
            if (!j_is_obj(el)) {
                snprintf(err, errsz, "%s must be a list of objects", akeys[i]);
                j_free(res);
                return NULL;
            }
        }
    }
    const jval_t *users = j_get(res, "users");
    for (jval_t *u = users->child; u; u = u->next) {
        if (!j_is_obj(u)) {
            snprintf(err, errsz, "users must contain objects");
            j_free(res);
            return NULL;
        }
    }
    return res;
}

static void migrate_legacy_conf_if_needed(const char *path)
{
    size_t pl = strlen(path);
    if (pl < 5 || strcmp(path + pl - 5, ".conf") != 0)
        return;
    char *raw = NULL;
    if (read_file_str(path, &raw, NULL) == 0) {
        char *p = raw;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '{') {
            free(raw);
            return;
        }
    }
    int kv_port = 8000;
    char kv_host[64] = "0.0.0.0";
    char kv_state[1024] = "";
    int kv_auth = -1;
    if (raw) {
        for (char *line = strtok(raw, "\r\n"); line; line = strtok(NULL, "\r\n")) {
            while (*line && isspace((unsigned char)*line)) line++;
            if (!*line || *line == '#')
                continue;
            char *eq = strchr(line, '=');
            if (!eq)
                continue;
            *eq++ = 0;
            char *k = line;
            size_t kl = strlen(k);
            while (kl && isspace((unsigned char)k[kl - 1])) k[--kl] = 0;
            while (*eq && isspace((unsigned char)*eq)) eq++;
            size_t vl = strlen(eq);
            while (vl && (isspace((unsigned char)eq[vl - 1]) || eq[vl - 1] == '"' || eq[vl - 1] == '\'')) eq[--vl] = 0;
            if (*eq == '"' || *eq == '\'') eq++;
            if (!strcmp(k, "ASTRA_PORT") || !strcmp(k, "PORT"))
                kv_port = atoi(eq) > 0 ? atoi(eq) : 8000;
            else if (!strcmp(k, "ASTRA_HOST") || !strcmp(k, "HOST"))
                snprintf(kv_host, sizeof kv_host, "%s", eq);
            else if (!strcmp(k, "ASTRA_STATE_FILE"))
                snprintf(kv_state, sizeof kv_state, "%s", eq);
            else if (!strcmp(k, "AUTH_ENABLE"))
                kv_auth = (!strcasecmp(eq, "true") || !strcmp(eq, "1") || !strcasecmp(eq, "yes"));
        }
        free(raw);
    }
    if (!kv_state[0]) {
        const char *bn = strrchr(path, '/');
        bn = bn ? bn + 1 : path;
        if (!strcmp(bn, "astrag.conf") && access("/var/lib/astrag/state.json", R_OK) == 0)
            snprintf(kv_state, sizeof kv_state, "/var/lib/astrag/state.json");
    }
    jval_t *merged = NULL;
    if (kv_state[0] && strcmp(kv_state, path) != 0) {
        char *sraw = NULL;
        if (read_file_str(kv_state, &sraw, NULL) == 0) {
            jval_t *st = j_parse(sraw);
            free(sraw);
            const jval_t *loaded = (st && j_is_obj(j_get(st, "config"))) ? j_get(st, "config") : st;
            if (j_is_obj(loaded)) {
                merged = default_cfg_obj(kv_port, kv_host);
                for (jval_t *c = loaded->child; c; c = c->next)
                    if (c->key)
                        j_set(merged, c->key, j_dup(c));
                j_set(merged, "port", j_int(kv_port));
                j_set(merged, "host", j_str(kv_host));
                if (kv_auth >= 0) {
                    jval_t *au = j_get(merged, "auth");
                    if (j_is_obj(au))
                        j_set(au, "enable", j_bool(kv_auth));
                }
            }
            j_free(st);
        }
    } else if (raw != NULL) {
        merged = default_cfg_obj(kv_port, kv_host);
        jval_t *au = j_get(merged, "auth");
        j_set(au, "enable", j_bool(kv_auth >= 0 ? kv_auth : 0));
    }
    if (merged) {
        jval_t *users = j_get(merged, "users");
        if (j_is_obj(users)) {
            for (jval_t *u = users->child; u; u = u->next) {
                const char *pw = j_get_str(u, "password", "");
                if (!strncmp(pw, "pbkdf2_sha256$", 14) && verify_password("admin", pw))
                    j_set(u, "password", j_str("admin"));
            }
        }
        atomic_write_file(path, "", 0, 0640);
        char *saved_path = strdup(g_conf_path);
        if (path != g_conf_path)
            snprintf(g_conf_path, sizeof g_conf_path, "%s", path);
        atomic_save(merged);
        if (saved_path) {
            if (strcmp(saved_path, g_conf_path) != 0)
                snprintf(g_conf_path, sizeof g_conf_path, "%s", saved_path);
            free(saved_path);
        }
        j_free(merged);
    }
}

static jval_t *load_disk_config(char *err, size_t errsz)
{
    migrate_legacy_conf_if_needed(g_conf_path);
    jval_t *cfg = default_cfg_obj(g_port, g_host);
    char *raw = NULL;
    if (read_file_str(g_conf_path, &raw, NULL) == 0) {
        char *t = raw;
        while (*t && isspace((unsigned char)*t)) t++;
        jval_t *data = *t ? j_parse(t) : j_obj();
        free(raw);
        if (!j_is_obj(data)) {
            j_free(data);
            j_free(cfg);
            snprintf(err, errsz, "Cannot parse configuration JSON");
            return NULL;
        }
        jval_t *loaded = j_is_obj(j_get(data, "config")) ? j_get(data, "config") : data;
        for (jval_t *c = loaded->child; c; c = c->next)
            if (c->key)
                j_set(cfg, c->key, j_dup(c));
        jval_t *users = j_get(cfg, "users");
        if (!j_is_obj(users) || !users->child) {
            jval_t *us = j_obj();
            j_set(us, "admin", default_admin_obj());
            j_set(cfg, "users", us);
        }
        const jval_t *streams_obj = j_get(data, "streams");
        if (!j_get(loaded, "make_stream") && j_is_obj(streams_obj)) {
            jval_t *ms = j_arr();
            for (jval_t *st = streams_obj->child; st; st = st->next) {
                if (j_is_obj(st) && st->key) {
                    jval_t *d = j_dup(st);
                    j_set(d, "id", j_str(st->key));
                    j_arr_add(ms, d);
                }
            }
            j_set(cfg, "make_stream", ms);
        }
        jval_t *ms = j_get(cfg, "make_stream");
        if (j_is_arr(ms)) {
            int idx = 0;
            for (jval_t *s = ms->child; s; s = s->next, idx++) {
                if (j_is_obj(s) && !j_get_str(s, "id", "")[0]) {
                    char genid[32];
                    snprintf(genid, sizeof genid, "a%05d", idx + 1);
                    j_set(s, "id", j_str(genid));
                }
            }
        }
        j_free(data);
    }
    const char *env_auth = getenv("ASTRA_AUTH_ENABLE");
    if (env_auth) {
        jval_t *au = j_get(cfg, "auth");
        j_set(au, "enable", j_bool(!strcasecmp(env_auth, "true") || !strcmp(env_auth, "1") || !strcasecmp(env_auth, "yes")));
    } else {
        jval_t *au = j_get(cfg, "auth");
        if (j_is_obj(au) && j_get_bool(au, "enable", 0) &&
            !j_get(au, "backend") && !j_get(au, "iptvportal") &&
            !j_get(au, "ministra") && !j_get(au, "smarty") &&
            !j_get(au, "http_ip_allow") && !j_get(au, "http_ip_deny") &&
            !j_get(au, "http_token_deny") && !j_get(au, "securetoken") &&
            !j_get(au, "promo")) {
            int has_user_tok = 0;
            const jval_t *us = j_get(cfg, "users");
            if (j_is_obj(us)) {
                for (const jval_t *u = us->child; u; u = u->next) {
                    const char *ut = j_get_str(u, "token", "");
                    if (*ut) { has_user_tok = 1; break; }
                }
            }
            if (!has_user_tok)
                j_set(au, "enable", j_bool(0));
        }
    }
    int cport = (int)j_get_int(cfg, "port", g_port);
    if (cport >= 1 && cport <= 65535)
        g_port = cport;
    j_set(cfg, "port", j_int(g_port));
    j_set(cfg, "control_port", j_int(g_port));
    const char *chost = j_get_str(cfg, "host", "");
    if (*chost)
        snprintf(g_host, sizeof g_host, "%s", chost);
    else
        j_set(cfg, "host", j_str(g_host));

    jval_t *val = validate_config(cfg, err, errsz);
    j_free(cfg);
    return val;
}

/* ----------------------------------------------------------- redaction */

static int is_secret_key(const char *k)
{
    return k && (strcasestr(k, "password") || strcasestr(k, "token") ||
                 strcasestr(k, "secret") || strcasestr(k, "passwd"));
}

static void strip_url_creds(const char *in, char *out, size_t outsz)
{
    const char *sc = strstr(in, "://");
    if (!sc) {
        snprintf(out, outsz, "%s", in);
        return;
    }
    size_t slen = (size_t)(sc + 3 - in);
    const char *p = sc + 3;
    const char *end = p + strcspn(p, "/?#");
    const char *at = memrchr(p, '@', (size_t)(end - p));
    const char *host_part = at ? at + 1 : p;
    const char *path_end = end + strcspn(end, "?#");
    snprintf(out, outsz, "%.*s%.*s", (int)slen, in, (int)(path_end - host_part), host_part);
}

static jval_t *redact_val(const jval_t *v, int strip_urls)
{
    if (!v)
        return j_null();
    if (v->type == J_OBJECT) {
        jval_t *o = j_obj();
        for (jval_t *c = v->child; c; c = c->next) {
            if (!c->key || is_secret_key(c->key))
                continue;
            if (strip_urls && (!strcasecmp(c->key, "pass") || !strcasecmp(c->key, "auth")))
                continue;
            j_set(o, c->key, redact_val(c, strip_urls));
        }
        return o;
    }
    if (v->type == J_ARRAY) {
        jval_t *a = j_arr();
        for (jval_t *c = v->child; c; c = c->next)
            j_arr_add(a, redact_val(c, strip_urls));
        return a;
    }
    if (strip_urls && v->type == J_STRING && v->str && strstr(v->str, "://")) {
        char buf[4096];
        strip_url_creds(v->str, buf, sizeof buf);
        return j_str(buf);
    }
    return j_dup(v);
}

/* ----------------------------------------------------------- channel sync */

static int has_active_output(const jval_t *s)
{
    if (j_get_str(s, "_cluster_host", NULL))
        return 0;
    const jval_t *outs = j_get(s, "output");
    if (!j_is_arr(outs))
        return 0;
    for (jval_t *it = outs->child; it; it = it->next) {
        if (!j_is_str(it))
            continue;
        const char *u = it->str;
        while (*u && isspace((unsigned char)*u)) u++;
        if (!*u)
            continue;
        const char *hash = strchr(u, '#');
        if (hash == u)
            continue;
        if (hash) {
            if (strcasestr(hash + 1, "disabled") || strcasestr(hash + 1, "enable=false") ||
                strcasestr(hash + 1, "enable=0"))
                continue;
        }
        return 1;
    }
    return 0;
}

static int stream_keep_active(const jval_t *s, double *idle_delay_out)
{
    double idly = 20.0;
    const jval_t *settings = j_get(g_cfg, "settings");
    const jval_t *ska = j_get(s, "http_keep_active");
    const jval_t *gka = j_get(settings, "http_keep_active");
    const jval_t *ka = ska ? ska : gka;
    int ka_val = 0;
    if (j_is_num(ka))
        ka_val = (int)ka->inum;
    else if (j_is_str(ka) && ka->str[0])
        ka_val = atoi(ka->str);
    if (ka_val > 0)
        idly = (double)ka_val;
    if (idle_delay_out)
        *idle_delay_out = idly;

    if (j_get_str(s, "_cluster_host", NULL))
        return 0;
    if (has_active_output(s))
        return 1;
    if (ka_val == -1)
        return 1;
    const jval_t *ins = j_get(s, "input");
    if (j_is_arr(ins)) {
        for (jval_t *it = ins->child; it; it = it->next) {
            if (j_is_str(it)) {
                const char *h = strchr(it->str, '#');
                if (h && strstr(h + 1, "keep_active"))
                    return 1;
            }
        }
    }
    return 0;
}

static channel_t *start_channel_from_json(const jval_t *s)
{
    const char *sid = j_get_str(s, "id", "");
    const char *name = j_get_str(s, "name", "");
    const jval_t *ins = j_get(s, "input");
    if (!*sid || !j_is_arr(ins) || !ins->child)
        return NULL;

    char *urls[MAX_URLS];
    int nu = 0;
    int is_cluster = j_get_str(s, "_cluster_host", NULL) != NULL;
    for (jval_t *it = ins->child; it && nu < MAX_URLS; it = it->next) {
        if (!j_is_str(it) || !it->str[0])
            continue;
        if (is_cluster) {
            /* Strip keep_active if any on cluster streams */
            char tmp[4096];
            snprintf(tmp, sizeof tmp, "%s", it->str);
            char *h = strchr(tmp, '#');
            if (h) {
                char outf[512] = "";
                for (char *tok = strtok(h + 1, "&"); tok; tok = strtok(NULL, "&")) {
                    if (!strncmp(tok, "keep_active", 11))
                        continue;
                    if (outf[0])
                        strncat(outf, "&", sizeof outf - strlen(outf) - 1);
                    strncat(outf, tok, sizeof outf - strlen(outf) - 1);
                }
                if (outf[0])
                    snprintf(h, sizeof tmp - (size_t)(h - tmp), "#%s", outf);
                else
                    *h = 0;
            }
            urls[nu++] = strdup(tmp);
        } else {
            urls[nu++] = strdup(it->str);
        }
    }
    if (nu == 0)
        return NULL;

    char *uouts[MAX_UDP_OUT];
    int nuo = 0;
    const jval_t *outs = j_get(s, "output");
    if (!is_cluster && j_is_arr(outs)) {
        for (jval_t *it = outs->child; it && nuo < MAX_UDP_OUT; it = it->next) {
            if (!j_is_str(it))
                continue;
            const char *u = it->str;
            if (!strncasecmp(u, "udp://", 6)) {
                const char *h = strchr(u, '#');
                if (h && (strcasestr(h, "disabled") || strcasestr(h, "enable=false") || strcasestr(h, "enable=0")))
                    continue;
                uouts[nuo++] = (char *)u;
            }
        }
    }

    const jval_t *hls_cfg = j_get(g_cfg, "hls");
    double seg_dur = j_get_num(hls_cfg, "duration", 3.0);
    int seg_keep = (int)j_get_int(hls_cfg, "quantity", 5);
    if (seg_dur < 1.0) seg_dur = 3.0;
    if (seg_dur > 10.0) seg_dur = 10.0;
    if (seg_keep < 2) seg_keep = 5;
    if (seg_keep > 12) seg_keep = 12;

    double idle_delay = 20.0;
    int ka = stream_keep_active(s, &idle_delay);
    channel_t *ch = ch_upsert(sid, seg_dur, seg_keep, name, urls, nu, ka, idle_delay, uouts, nuo);
    if (ch && is_cluster) {
        ch->is_cluster = 1;
        snprintf(ch->cluster_host, sizeof ch->cluster_host, "%s", j_get_str(s, "_cluster_host", ""));
        snprintf(ch->cluster_orig_id, sizeof ch->cluster_orig_id, "%s", j_get_str(s, "_cluster_orig_id", sid));
    }
    for (int i = 0; i < nu; i++)
        free(urls[i]);
    return ch;
}

static int channel_matches_json(channel_t *ch, const jval_t *s)
{
    if (!ch || !s)
        return 0;
    if (strcmp(ch->name, j_get_str(s, "name", "")) != 0)
        return 0;
    const jval_t *ins = j_get(s, "input");
    int cnt = j_arr_len(ins);
    if (cnt != ch->nurls)
        return 0;
    int i = 0;
    for (jval_t *it = ins->child; it; it = it->next, i++) {
        if (!j_is_str(it) || strcmp(it->str, ch->urls[i]) != 0)
            return 0;
    }
    double idly = 20.0;
    int ka = stream_keep_active(s, &idly);
    if (ka != ch->keep_active || (int)idly != (int)ch->idle_delay)
        return 0;
    return 1;
}

static void sync_extra_ports(const jval_t *cfg)
{
    if (getenv("ASTRA_DISABLE_EXTRA_PORTS") && !strcmp(getenv("ASTRA_DISABLE_EXTRA_PORTS"), "1"))
        return;
    int wanted[64];
    int nw = 0;
    const jval_t *settings = j_get(cfg, "settings");
    const char *skeys[2] = {"control_port", "http_play_port"};
    for (int k = 0; k < 2; k++) {
        const jval_t *v = j_get(settings, skeys[k]);
        int p = 0;
        if (j_is_num(v))
            p = (int)v->inum;
        else if (j_is_str(v))
            p = atoi(v->str);
        if (p >= 1 && p <= 65535 && p != g_port && nw < 64) {
            int dup = 0;
            for (int j = 0; j < nw; j++) dup |= wanted[j] == p;
            if (!dup) wanted[nw++] = p;
        }
    }
    const jval_t *ms = j_get(cfg, "make_stream");
    if (j_is_arr(ms)) {
        for (jval_t *s = ms->child; s; s = s->next) {
            if (!j_get_bool(s, "enable", 1))
                continue;
            const jval_t *outs = j_get(s, "output");
            if (!j_is_arr(outs))
                continue;
            for (jval_t *it = outs->child; it; it = it->next) {
                if (!j_is_str(it))
                    continue;
                if (strncasecmp(it->str, "http://", 7) && strncasecmp(it->str, "https://", 8))
                    continue;
                const char *p = strstr(it->str, "://") + 3;
                const char *end = p + strcspn(p, "/?#");
                const char *at = memrchr(p, '@', (size_t)(end - p));
                if (at) p = at + 1;
                const char *col = memchr(p, ':', (size_t)(end - p));
                if (col) {
                    int pt = atoi(col + 1);
                    if (pt >= 1 && pt <= 65535 && pt != g_port && nw < 64) {
                        int dup = 0;
                        for (int j = 0; j < nw; j++) dup |= wanted[j] == pt;
                        if (!dup) wanted[nw++] = pt;
                    }
                }
            }
        }
    }
    /* Remove any listener not g_port and not in wanted */
    int retry;
    do {
        retry = 0;
        for (channel_t *dummy = NULL; ; ) { (void)dummy; break; }
        /* Iterate 1..65535 is slow; track our own extra ports */
        static int active_extras[64];
        static int n_active = 0;
        for (int i = 0; i < n_active; ) {
            int p = active_extras[i];
            int keep = 0;
            for (int j = 0; j < nw; j++) keep |= wanted[j] == p;
            if (!keep) {
                listener_del(p);
                active_extras[i] = active_extras[--n_active];
            } else {
                i++;
            }
        }
        for (int j = 0; j < nw; j++) {
            int p = wanted[j];
            if (!listener_has(p)) {
                if (listener_add(g_host, p) == 0 && n_active < 64)
                    active_extras[n_active++] = p;
            }
        }
        (void)retry;
    } while (0);
}

static void sync_local_engines(const jval_t *cfg, int rebuild)
{
    const jval_t *ms = j_get(cfg, "make_stream");
    /* Delete channels that are removed, disabled, or changed */
    for (channel_t *ch = g_channels, *nx; ch; ch = nx) {
        nx = ch->next;
        if (ch->is_cluster)
            continue;
        const jval_t *match = NULL;
        for (jval_t *s = ms->child; s; s = s->next) {
            if (!strcmp(j_get_str(s, "id", ""), ch->id)) {
                match = s;
                break;
            }
        }
        if (rebuild || !match || !j_get_bool(match, "enable", 1) || !j_get_bool(match, "active", 1) ||
            !j_arr_len(j_get(match, "input")) || !channel_matches_json(ch, match)) {
            ch_del(ch);
        }
    }
    /* Start new/missing enabled local channels */
    for (jval_t *s = ms->child; s; s = s->next) {
        if (!j_get_bool(s, "enable", 1) || !j_get_bool(s, "active", 1))
            continue;
        if (!j_arr_len(j_get(s, "input")))
            continue;
        const char *sid = j_get_str(s, "id", "");
        if (!ch_find(sid))
            start_channel_from_json(s);
    }
}

static int apply_config(jval_t *candidate, int persist, int rebuild, char *errbuf, size_t errsz)
{
    jval_t *val = validate_config(candidate, errbuf, errsz);
    if (!val)
        return -1;
    int servers_changed = !g_cfg || !j_equal(j_get(val, "servers"), j_get(g_cfg, "servers"));
    int ms_changed = !g_cfg || !j_equal(j_get(val, "make_stream"), j_get(g_cfg, "make_stream")) ||
                     !j_equal(j_get(val, "hls"), j_get(g_cfg, "hls")) ||
                     !j_equal(j_get(val, "settings"), j_get(g_cfg, "settings")) || rebuild;

    j_free(g_cfg);
    g_cfg = val;
    if (ms_changed)
        sync_local_engines(g_cfg, rebuild);
    if (persist)
        atomic_save(g_cfg);
    sync_extra_ports(g_cfg);
    if (servers_changed || rebuild)
        cluster_sync_start();
    return 0;
}

/* ----------------------------------------------------------- stream resolution */

static const jval_t *find_stream_cfg(const char *sid)
{
    if (!sid || !g_cfg)
        return NULL;
    const jval_t *ms = j_get(g_cfg, "make_stream");
    if (j_is_arr(ms)) {
        for (jval_t *s = ms->child; s; s = s->next) {
            if (!strcmp(j_get_str(s, "id", ""), sid))
                return s;
        }
    }
    for (int i = 0; i < g_ncstreams; i++) {
        if (!strcmp(g_cstreams[i].eff_id, sid))
            return g_cstreams[i].cfg;
    }
    return NULL;
}

static const char *resolve_stream_id(const char *stream_id, const char *host_hint)
{
    static char clean[128];
    if (!stream_id || !*stream_id)
        return NULL;
    const jval_t *ms = j_get(g_cfg, "make_stream");
    if (!host_hint || !*host_hint) {
        if (j_is_arr(ms)) {
            for (jval_t *s = ms->child; s; s = s->next) {
                if (!strcmp(j_get_str(s, "id", ""), stream_id) && ch_find(stream_id))
                    return j_get_str(s, "id", "");
            }
        }
    }
    if (host_hint && *host_hint) {
        for (int i = 0; i < g_ncalias; i++) {
            if (!strcmp(g_calias[i].key, host_hint) && !strcmp(g_calias[i].orig_id, stream_id))
                return g_calias[i].eff_id;
        }
    }
    for (int i = 0; i < g_ncstreams; i++) {
        if (!strcmp(g_cstreams[i].eff_id, stream_id) && ch_find(stream_id))
            return g_cstreams[i].eff_id;
    }
    for (int i = 0; i < g_ncalias; i++) {
        if (!g_calias[i].key[0] && !strcmp(g_calias[i].orig_id, stream_id))
            return g_calias[i].eff_id;
    }
    if (!host_hint || !*host_hint) {
        if (j_is_arr(ms)) {
            for (jval_t *s = ms->child; s; s = s->next) {
                if (!strcmp(j_get_str(s, "id", ""), stream_id))
                    return j_get_str(s, "id", "");
            }
        }
    }
    size_t sl = strlen(stream_id);
    if (sl > 3 && !strcmp(stream_id + sl - 3, ".ts") && sl - 3 < sizeof clean) {
        memcpy(clean, stream_id, sl - 3);
        clean[sl - 3] = 0;
        return resolve_stream_id(clean, host_hint);
    }
    return NULL;
}

static channel_t *ensure_channel_started(const char *sid)
{
    channel_t *ch = ch_find(sid);
    if (ch)
        return ch;
    const jval_t *s = find_stream_cfg(sid);
    if (!s || !j_get_bool(s, "enable", 1) || !j_get_bool(s, "active", 1))
        return NULL;
    return start_channel_from_json(s);
}

/* ----------------------------------------------------------- cluster sync */

static void rewrite_remote_url(const char *in, const char *remote_host, char *out, size_t outsz)
{
    out[0] = 0;
    if (!in || !*in)
        return;
    const char *hash = strchr(in, '#');
    size_t blen = hash ? (size_t)(hash - in) : strlen(in);
    char base[4096];
    snprintf(base, sizeof base, "%.*s", (int)blen, in);
    int https = 0;
    const char *p = base;
    if (!strncasecmp(p, "http://", 7))
        p += 7;
    else if (!strncasecmp(p, "https://", 8)) {
        https = 1;
        p += 8;
    } else
        return;

    const char *auth_end = p + strcspn(p, "/?");
    const char *at = memrchr(p, '@', (size_t)(auth_end - p));
    const char *hp = at ? at + 1 : p;
    const char *col = memchr(hp, ':', (size_t)(auth_end - hp));
    const char *he = col ? col : auth_end;
    char host[256];
    snprintf(host, sizeof host, "%.*s", (int)(he - hp), hp);
    if (!strcmp(host, "0") || !strcmp(host, "0.0.0.0") || !strcmp(host, "127.0.0.1") || !strcasecmp(host, "localhost")) {
        buf_t b = {0};
        buf_fmt(&b, "%s://", https ? "https" : "http");
        if (at)
            buf_add(&b, p, (size_t)(at - p + 1));
        buf_str(&b, remote_host);
        if (col)
            buf_add(&b, col, (size_t)(auth_end - col));
        buf_str(&b, auth_end);
        if (hash)
            buf_str(&b, hash);
        snprintf(out, outsz, "%.*s", (int)b.len, b.p ? (char *)b.p : "");
        buf_free(&b);
    } else {
        snprintf(out, outsz, "%s", in);
    }
}

static void ccache_set(const char *hp, const jval_t *cfg)
{
    for (int i = 0; i < g_nccache; i++) {
        if (!strcmp(g_ccache[i].host_port, hp)) {
            j_free(g_ccache[i].cfg);
            g_ccache[i].cfg = j_dup(cfg);
            return;
        }
    }
    if (g_nccache < MAX_CLUSTER_SRV) {
        snprintf(g_ccache[g_nccache].host_port, sizeof g_ccache[0].host_port, "%s", hp);
        g_ccache[g_nccache].cfg = j_dup(cfg);
        g_nccache++;
    }
}

static const jval_t *ccache_get(const char *hp)
{
    for (int i = 0; i < g_nccache; i++)
        if (!strcmp(g_ccache[i].host_port, hp))
            return g_ccache[i].cfg;
    return NULL;
}

static void calias_add(const char *key, const char *orig_id, const char *eff_id)
{
    cluster_alias_t *n = realloc(g_calias, (size_t)(g_ncalias + 1) * sizeof *g_calias);
    if (!n)
        return;
    g_calias = n;
    cluster_alias_t *a = &g_calias[g_ncalias++];
    snprintf(a->key, sizeof a->key, "%s", key ? key : "");
    snprintf(a->orig_id, sizeof a->orig_id, "%s", orig_id);
    snprintf(a->eff_id, sizeof a->eff_id, "%s", eff_id);
}

static void cluster_sync_apply(csync_ctx_t *ctx)
{
    /* Clear old cstreams and calias cleanly; keep local channel IDs separate */
    for (int i = 0; i < g_ncstreams; i++)
        j_free(g_cstreams[i].cfg);
    g_ncstreams = 0;
    free(g_calias);
    g_calias = NULL;
    g_ncalias = 0;

    int n_srv = j_arr_len(ctx->servers);
    for (int idx = 0; idx < n_srv && idx < MAX_CLUSTER_SRV; idx++) {
        const jval_t *srv = j_arr_get(ctx->servers, idx);
        if (!j_is_obj(srv))
            continue;
        const jval_t *sen = j_get(srv, "enable");
        if (sen && (j_bool_val(sen) == 0 || (j_is_str(sen) && !strcasecmp(sen->str, "false"))))
            continue;
        const char *rhost = j_get_str(srv, "host", "");
        if (!*rhost)
            continue;
        int rport = (int)j_get_int(srv, "port", 8000);
        if (j_is_str(j_get(srv, "port")))
            rport = atoi(j_get_str(srv, "port", "8000"));
        if (rport <= 0) rport = 8000;
        const char *ruser = j_get_str(srv, "user", "");
        const char *rpass = j_get_str(srv, "pass", "");
        char hp[128];
        snprintf(hp, sizeof hp, "%s:%d", rhost, rport);
        const char *srv_name = j_get_str(srv, "name", hp);
        if (!*srv_name) srv_name = hp;

        const jval_t *rcfg = ctx->results[idx] ? ctx->results[idx] : ccache_get(hp);
        if (!j_is_obj(rcfg))
            continue;

        const jval_t *rsettings = j_get(rcfg, "settings");
        const jval_t *rauth = j_get(rcfg, "auth");
        const jval_t *rusers = j_get(rcfg, "users");
        int has_http_play = j_get_bool(rsettings, "http_play_stream", 0) ||
                            j_get_bool(rsettings, "http_play_hls", 0);
        int play_port = (int)j_get_int(rsettings, "http_play_port", rport);
        if (j_is_str(j_get(rsettings, "http_play_port")))
            play_port = atoi(j_get_str(rsettings, "http_play_port", "")) ?: rport;

        const jval_t *rms = j_get(rcfg, "make_stream");
        if (!j_is_arr(rms))
            continue;
        for (jval_t *rs = rms->child; rs && g_ncstreams < MAX_CLUSTER_STREAMS; rs = rs->next) {
            if (!j_is_obj(rs))
                continue;
            const jval_t *ren = j_get(rs, "enable");
            if (ren && (j_bool_val(ren) == 0 || (j_is_str(ren) && !strcasecmp(ren->str, "false"))))
                continue;
            const char *orig_id = j_get_str(rs, "id", "");
            if (!*orig_id)
                continue;
            if (!strcasecmp(j_get_str(rs, "type", "spts"), "mpts") && !j_arr_len(j_get(rs, "output")))
                continue;

            /* Build proxy_inputs */
            jval_t *pins = j_arr();
            char play_url[512];
            snprintf(play_url, sizeof play_url, "http://%s:%d/play/%s", rhost, play_port, orig_id);
            if (j_get_bool(rauth, "enable", 0) && j_is_obj(rusers)) {
                const jval_t *ru = *ruser ? j_get(rusers, ruser) : NULL;
                const char *rtok = ru ? j_get_str(ru, "token", NULL) : NULL;
                if (rtok && *rtok) {
                    snprintf(play_url + strlen(play_url), sizeof play_url - strlen(play_url), "?token=%s", rtok);
                } else if (*ruser && *rpass) {
                    snprintf(play_url + strlen(play_url), sizeof play_url - strlen(play_url), "?auth=%s:%s", ruser, rpass);
                } else {
                    for (jval_t *ui = rusers->child; ui; ui = ui->next) {
                        if (j_is_obj(ui) && j_get_bool(ui, "enable", 1)) {
                            const char *tok = j_get_str(ui, "token", NULL);
                            if (tok && *tok) {
                                snprintf(play_url + strlen(play_url), sizeof play_url - strlen(play_url), "?token=%s", tok);
                                break;
                            }
                        }
                    }
                }
            }

            char *cand[MAX_URLS];
            int ncand = 0;
            /* Collect candidates in priority order */
            if (has_http_play)
                cand[ncand++] = strdup(play_url);
            const jval_t *routs = j_get(rs, "output");
            jval_t *http_outs = j_arr();
            if (j_is_arr(routs)) {
                for (jval_t *it = routs->child; it; it = it->next) {
                    if (!j_is_str(it)) continue;
                    char rw[4096];
                    rewrite_remote_url(it->str, rhost, rw, sizeof rw);
                    if (rw[0] && ncand < MAX_URLS) {
                        int dup = 0;
                        for (int j = 0; j < ncand; j++) dup |= !strcmp(cand[j], rw);
                        if (!dup) cand[ncand++] = strdup(rw);
                    }
                    if (!strncasecmp(it->str, "http://", 7) || !strncasecmp(it->str, "https://", 8))
                        j_arr_add(http_outs, j_str(it->str));
                }
            }
            if (!has_http_play && ncand < MAX_URLS) {
                int dup = 0;
                for (int j = 0; j < ncand; j++) dup |= !strcmp(cand[j], play_url);
                if (!dup) cand[ncand++] = strdup(play_url);
            }
            const jval_t *rins = j_get(rs, "input");
            if (j_is_arr(rins)) {
                for (jval_t *it = rins->child; it && ncand < MAX_URLS; it = it->next) {
                    if (!j_is_str(it)) continue;
                    char rw[4096];
                    rewrite_remote_url(it->str, rhost, rw, sizeof rw);
                    if (rw[0]) {
                        int dup = 0;
                        for (int j = 0; j < ncand; j++) dup |= !strcmp(cand[j], rw);
                        if (!dup) cand[ncand++] = strdup(rw);
                    }
                }
            }
            for (int i = 0; i < ncand; i++) {
                j_arr_add(pins, j_str(cand[i]));
                free(cand[i]);
            }
            if (ncand == 0) {
                j_free(pins);
                j_free(http_outs);
                continue;
            }

            char prefixed_id[128], eff_id[128];
            snprintf(prefixed_id, sizeof prefixed_id, "c%d_%s", idx + 1, orig_id);
            int local_conflict = 0;
            const jval_t *lms = j_get(g_cfg, "make_stream");
            for (jval_t *ls = lms->child; ls; ls = ls->next)
                if (!strcmp(j_get_str(ls, "id", ""), orig_id)) local_conflict = 1;
            int cluster_conflict = 0;
            for (int i = 0; i < g_ncstreams; i++)
                if (!strcmp(g_cstreams[i].eff_id, orig_id)) cluster_conflict = 1;
            snprintf(eff_id, sizeof eff_id, "%s",
                     (has_http_play && !local_conflict && !cluster_conflict) ? orig_id : prefixed_id);

            jval_t *pcfg = j_obj();
            j_set(pcfg, "id", j_str(eff_id));
            j_set(pcfg, "name", j_str(j_get_str(rs, "name", orig_id)));
            j_set(pcfg, "type", j_str(j_get_str(rs, "type", "spts")));
            j_set(pcfg, "enable", j_bool(1));
            j_set(pcfg, "active", j_bool(1));
            j_set(pcfg, "input", pins);
            j_set(pcfg, "output", http_outs);
            const jval_t *rgroups = j_get(rs, "groups");
            jval_t *groups = j_is_obj(rgroups) && rgroups->child ? j_dup(rgroups) : j_obj();
            if (!groups->child && *srv_name)
                j_set(groups, "Cluster", j_str(srv_name));
            j_set(pcfg, "groups", groups);
            j_set(pcfg, "http_keep_active", j_int(0));
            j_set(pcfg, "_cluster_host", j_str(hp));
            j_set(pcfg, "_cluster_orig_id", j_str(orig_id));
            j_set(pcfg, "_cluster_srv_idx", j_int(idx + 1));
            j_set(pcfg, "_cluster_srv_name", j_str(srv_name));
            j_set(pcfg, "_cluster_enabled", j_bool(1));

            cluster_stream_t *cs = &g_cstreams[g_ncstreams++];
            snprintf(cs->eff_id, sizeof cs->eff_id, "%s", eff_id);
            snprintf(cs->orig_id, sizeof cs->orig_id, "%s", orig_id);
            snprintf(cs->host_port, sizeof cs->host_port, "%s", hp);
            snprintf(cs->srv_name, sizeof cs->srv_name, "%s", srv_name);
            cs->srv_idx = idx + 1;
            cs->cfg = pcfg;

            calias_add(hp, orig_id, eff_id);
            calias_add(srv_name, orig_id, eff_id);
            char idx_s[16];
            snprintf(idx_s, sizeof idx_s, "%d", idx + 1);
            calias_add(idx_s, orig_id, eff_id);
            calias_add("", prefixed_id, eff_id);
            if (has_http_play)
                calias_add("", orig_id, eff_id);
        }
    }

    /* Stop dead cluster engines, start/update current ones */
    for (channel_t *ch = g_channels, *nx; ch; ch = nx) {
        nx = ch->next;
        if (!ch->is_cluster)
            continue;
        int keep = 0;
        for (int i = 0; i < g_ncstreams; i++)
            if (!strcmp(g_cstreams[i].eff_id, ch->id)) { keep = 1; break; }
        if (!keep)
            ch_del(ch);
    }
    for (int i = 0; i < g_ncstreams; i++) {
        channel_t *ch = ch_find(g_cstreams[i].eff_id);
        if (!ch || !channel_matches_json(ch, g_cstreams[i].cfg))
            start_channel_from_json(g_cstreams[i].cfg);
    }
}

typedef struct {
    int gen;
    int idx;
    char hp[128];
    buf_t body;
} csync_req_t;

static void csync_head(fetch_t *f) { (void)f; }
static void csync_data(fetch_t *f, const uint8_t *d, size_t n)
{
    csync_req_t *r = f->owner;
    if (r->body.len + n < 16u * 1024 * 1024)
        buf_add(&r->body, d, n);
}
static void csync_done(fetch_t *f, int ok, const char *err)
{
    (void)err;
    csync_req_t *r = f->owner;
    if (!g_csync || r->gen != g_csync->gen) {
        buf_free(&r->body);
        free(r);
        return;
    }
    if (ok && f->status == 200 && r->body.len > 0) {
        buf_add(&r->body, "", 1);
        jval_t *parsed = j_parse((const char *)r->body.p);
        if (j_is_obj(parsed)) {
            g_csync->results[r->idx] = parsed;
            ccache_set(r->hp, parsed);
        } else {
            j_free(parsed);
        }
    }
    buf_free(&r->body);
    g_csync->pending--;
    if (g_csync->pending <= 0) {
        cluster_sync_apply(g_csync);
        for (int i = 0; i < MAX_CLUSTER_SRV; i++)
            j_free(g_csync->results[i]);
        j_free(g_csync->servers);
        free(g_csync);
        g_csync = NULL;
    }
    free(r);
}
static const fetch_cb_t g_csync_cb = {csync_head, csync_data, csync_done};

static void cluster_sync_start(void)
{
    g_next_csync = g_now + 45.0;
    if (!g_cfg)
        return;
    const jval_t *servers = j_get(g_cfg, "servers");
    if (!j_is_arr(servers))
        return;

    if (g_csync) {
        for (int i = 0; i < MAX_CLUSTER_SRV; i++) j_free(g_csync->results[i]);
        j_free(g_csync->servers);
        free(g_csync);
        g_csync = NULL;
    }
    csync_ctx_t *ctx = calloc(1, sizeof *ctx);
    ctx->gen = ++g_csync_gen;
    ctx->servers = j_dup(servers);
    g_csync = ctx;

    int n = j_arr_len(servers);
    for (int i = 0; i < n && i < MAX_CLUSTER_SRV; i++) {
        const jval_t *srv = j_arr_get(servers, i);
        if (!j_is_obj(srv))
            continue;
        const jval_t *sen = j_get(srv, "enable");
        if (sen && (j_bool_val(sen) == 0 || (j_is_str(sen) && !strcasecmp(sen->str, "false"))))
            continue;
        const char *rhost = j_get_str(srv, "host", "");
        if (!*rhost)
            continue;
        int rport = (int)j_get_int(srv, "port", 8000);
        if (j_is_str(j_get(srv, "port")))
            rport = atoi(j_get_str(srv, "port", "8000"));
        if (rport <= 0) rport = 8000;
        const char *ruser = j_get_str(srv, "user", "");
        const char *rpass = j_get_str(srv, "pass", "");

        char url[512], extra[768] = "Content-Type: application/json\r\n";
        snprintf(url, sizeof url, "http://%s:%d/control/", rhost, rport);
        if (*ruser) {
            char cred[256], b64c[384];
            if (*rpass) snprintf(cred, sizeof cred, "%s:%s", ruser, rpass);
            else snprintf(cred, sizeof cred, "%s", ruser);
            b64_encode((const uint8_t *)cred, strlen(cred), b64c, sizeof b64c);
            snprintf(extra + strlen(extra), sizeof extra - strlen(extra), "Authorization: Basic %s\r\n", b64c);
        }
        csync_req_t *rq = calloc(1, sizeof *rq);
        rq->gen = ctx->gen;
        rq->idx = i;
        snprintf(rq->hp, sizeof rq->hp, "%s:%d", rhost, rport);
        const char *payload = "{\"cmd\":\"load\"}";
        if (fetch_start_ex("POST", url, "AstraG/2.0", extra, payload, strlen(payload),
                           &g_csync_cb, rq, 6.0, 6.0)) {
            ctx->pending++;
        } else {
            free(rq);
        }
    }
    if (ctx->pending == 0) {
        cluster_sync_apply(ctx);
        j_free(ctx->servers);
        free(ctx);
        g_csync = NULL;
    }
}

/* ----------------------------------------------------------- WebSocket & stats */

static void ws_send_json(front_t *fr, const jval_t *v)
{
    char *s = j_print(v, 0);
    if (s) {
        ws_send_text(fr, s, strlen(s));
        free(s);
    }
}

static void broadcast_ws(const char *scope, jval_t *payload)
{
    int has_admin = 0, has_obs = 0;
    for (front_t *fr = g_fronts; fr; fr = fr->gnext) {
        if (fr->ev.dead || fr->mode != FR_WS || fr->ws_is_cluster || !fr->ws_authed)
            continue;
        if (fr->ws_admin)
            has_admin = 1;
        else
            has_obs = 1;
    }
    if (!has_admin && !has_obs)
        return;

    jval_t *admin_msg = NULL;
    jval_t *obs_msg = NULL;
    char *admin_txt = NULL, *obs_txt = NULL;

    for (front_t *fr = g_fronts, *nx; fr; fr = nx) {
        nx = fr->gnext;
        if (fr->ev.dead || fr->mode != FR_WS || fr->ws_is_cluster || !fr->ws_authed)
            continue;
        if (j_get_bool(j_get(g_cfg, "auth"), "enable", 0) || fr->ws_login[0]) {
            if (fr->ws_login[0]) {
                const jval_t *u = j_get(j_get(g_cfg, "users"), fr->ws_login);
                if (!u || j_get_bool(u, "enable", 1) == 0) {
                    ws_send_close(fr, 1008);
                    continue;
                }
            }
        }
        if (fr->ws_admin) {
            if (!admin_msg) {
                admin_msg = j_obj();
                j_set(admin_msg, "scope", j_str(scope));
                jval_t *ra = redact_val(payload, 0);
                for (jval_t *c = ra->child; c; c = c->next)
                    if (c->key) j_set(admin_msg, c->key, j_dup(c));
                j_free(ra);
                admin_txt = j_print(admin_msg, 0);
            }
            if (admin_txt) ws_send_text(fr, admin_txt, strlen(admin_txt));
        } else {
            if (!obs_msg) {
                obs_msg = j_obj();
                j_set(obs_msg, "scope", j_str(scope));
                jval_t *ro = redact_val(payload, 1);
                for (jval_t *c = ro->child; c; c = c->next)
                    if (c->key) j_set(obs_msg, c->key, j_dup(c));
                j_free(ro);
                obs_txt = j_print(obs_msg, 0);
            }
            if (obs_txt) ws_send_text(fr, obs_txt, strlen(obs_txt));
        }
    }
    free(admin_txt);
    free(obs_txt);
    j_free(admin_msg);
    j_free(obs_msg);
}

static void broadcast_cluster_ws(const char *host_port, const char *scope, jval_t *payload)
{
    if (!host_port || !*host_port)
        return;
    int any = 0;
    for (front_t *fr = g_fronts; fr; fr = fr->gnext) {
        if (!fr->ev.dead && fr->mode == FR_WS && fr->ws_is_cluster && fr->ws_authed &&
            !strcmp(fr->ws_cluster_host, host_port)) {
            any = 1;
            break;
        }
    }
    if (!any)
        return;
    jval_t *msg = j_obj();
    j_set(msg, "scope", j_str(scope));
    for (jval_t *c = payload->child; c; c = c->next)
        if (c->key) j_set(msg, c->key, j_dup(c));
    char *txt = j_print(msg, 0);
    j_free(msg);
    if (!txt)
        return;
    size_t tl = strlen(txt);
    for (front_t *fr = g_fronts, *nx; fr; fr = nx) {
        nx = fr->gnext;
        if (fr->ev.dead || fr->mode != FR_WS || !fr->ws_is_cluster || !fr->ws_authed)
            continue;
        if (!strcmp(fr->ws_cluster_host, host_port))
            ws_send_text(fr, txt, tl);
    }
    free(txt);
}

static void revoke_account_sockets(const char *login)
{
    if (!login || !*login)
        return;
    for (front_t *fr = g_fronts, *nx; fr; fr = nx) {
        nx = fr->gnext;
        if (!fr->ev.dead && fr->mode == FR_WS && !fr->ws_is_cluster && !strcmp(fr->ws_login, login))
            ws_send_close(fr, 1008);
    }
}

void ctl_ws_on_message(front_t *fr, const char *msg, size_t len)
{
    jval_t *v = j_parse_n(msg, len);
    if (!j_is_obj(v)) {
        j_free(v);
        jval_t *e = j_obj();
        j_set(e, "scope", j_str("error"));
        j_set(e, "error", j_str("Invalid JSON"));
        ws_send_json(fr, e);
        j_free(e);
        return;
    }
    const char *scope = j_get_str(v, "scope", "");
    if (!strcmp(scope, "ping")) {
        jval_t *p = j_obj();
        j_set(p, "scope", j_str("ping"));
        ws_send_json(fr, p);
        j_free(p);
        j_free(v);
        return;
    }
    if (fr->ws_is_cluster) {
        if (!strcmp(scope, "auth")) {
            fr->ws_authed = 1;
            char id[33];
            gen_uuid_hex(id, sizeof id, 16);
            jval_t *a = j_obj();
            j_set(a, "scope", j_str("auth"));
            j_set(a, "id", j_str(id));
            j_set(a, "authorized", j_bool(1));
            ws_send_json(fr, a);
            j_free(a);
        }
        j_free(v);
        return;
    }
    if (strcmp(scope, "auth") != 0) {
        jval_t *e = j_obj();
        j_set(e, "scope", j_str("error"));
        j_set(e, "error", j_str("Authentication message required"));
        ws_send_json(fr, e);
        j_free(e);
        j_free(v);
        return;
    }
    const char *auth_str = j_get_str(v, "auth", NULL);
    auth_res_t res = check_identity(auth_str, fr->ip, 0, 1);
    j_free(v);
    if (!res.ok) {
        fr->ws_authed = 0;
        jval_t *a = j_obj();
        j_set(a, "scope", j_str("auth"));
        j_set(a, "authorized", j_bool(0));
        ws_send_json(fr, a);
        j_free(a);
        return;
    }
    fr->ws_authed = 1;
    fr->ws_admin = res.admin;
    snprintf(fr->ws_login, sizeof fr->ws_login, "%s", res.login);
    char id[33];
    gen_uuid_hex(id, sizeof id, 16);
    jval_t *a = j_obj();
    j_set(a, "scope", j_str("auth"));
    j_set(a, "id", j_str(id));
    j_set(a, "authorized", j_bool(1));
    ws_send_json(fr, a);
    j_free(a);
}

void ctl_ws_on_close(front_t *fr)
{
    fr->ws_authed = 0;
}

void ctl_on_sess_add(front_t *fr, channel_t *ch) { (void)fr; (void)ch; }
void ctl_on_sess_del(front_t *fr) { (void)fr; }

void ctl_on_ch_idle(channel_t *ch)
{
    if (!ch->was_active_ws)
        return;
    ch->was_active_ws = 0;
    jval_t *ev = j_obj();
    j_set(ev, "channel_id", j_str(ch->id));
    j_set(ev, "input_id", j_int(ch->cur + 1));
    j_set(ev, "idle", j_bool(1));
    j_set(ev, "onair", j_bool(0));
    j_set(ev, "bitrate", j_int(0));
    j_set(ev, "sessions", j_int(0));
    broadcast_ws("stream_event", ev);
    if (ch->is_cluster && ch->cluster_host[0]) {
        j_set(ev, "channel_id", j_str(ch->cluster_orig_id));
        broadcast_cluster_ws(ch->cluster_host, "stream_event", ev);
    }
    j_free(ev);
}

static void emit_scan_for(scan_t *sc)
{
    const char *rsid = resolve_stream_id(sc->stream_id, sc->cluster_host);
    if (!rsid) rsid = sc->stream_id;
    channel_t *ch = ensure_channel_started(rsid);
    if (ch)
        ch_wake(ch);

    jval_t *pat = NULL;
    jval_t *pmts = j_arr();
    int total_br = (ch && ch->bitrate > 0) ? (int)(ch->bitrate / 1000.0 + 0.5) : 0;

    if (ch && ch->npmt > 0) {
        pat = j_obj();
        j_set(pat, "psi", j_str("pat"));
        j_set(pat, "tsid", j_int(ch->tsid));
        jval_t *progs = j_arr();
        jval_t *streams = j_arr();
        for (int pid = 0; pid < 8191; pid++) {
            if (ch->kind[pid] && ch->kind[pid] != K_PMT) {
                jval_t *st = j_obj();
                j_set(st, "pid", j_int(pid));
                j_set(st, "type_id", j_int(ch->stype[pid]));
                j_set(st, "type_name", j_str(ch->kind[pid] == K_VIDEO ? "VIDEO" : (ch->kind[pid] == K_AUDIO ? "AUDIO" : "DATA")));
                j_set(st, "descriptors", j_arr());
                j_arr_add(streams, st);
            }
        }
        for (int i = 0; i < ch->npmt; i++) {
            jval_t *pr = j_obj();
            j_set(pr, "pnr", j_int(ch->pnr[i]));
            j_set(pr, "pid", j_int(ch->pmt_pid[i]));
            j_arr_add(progs, pr);

            jval_t *pmt = j_obj();
            j_set(pmt, "psi", j_str("pmt"));
            j_set(pmt, "pnr", j_int(ch->pnr[i]));
            j_set(pmt, "pid", j_int(ch->pmt_pid[i]));
            j_set(pmt, "pcr", j_int(ch->pcr_pid >= 0 ? ch->pcr_pid : 8191));
            j_set(pmt, "descriptors", j_arr());
            j_set(pmt, "streams", i == 0 ? j_dup(streams) : j_arr());
            j_arr_add(pmts, pmt);
        }
        j_free(streams);
        j_set(pat, "programs", progs);
    }

    if (pat) {
        jval_t *m = j_obj();
        j_set(m, "data", pat);
        broadcast_ws("scan", m);
        if (sc->cluster_host[0]) broadcast_cluster_ws(sc->cluster_host, "scan", m);
        j_free(m);
    }
    for (jval_t *p = pmts->child; p; p = p->next) {
        jval_t *m = j_obj();
        j_set(m, "data", j_dup(p));
        broadcast_ws("scan", m);
        if (sc->cluster_host[0]) broadcast_cluster_ws(sc->cluster_host, "scan", m);
        j_free(m);
    }
    j_free(pmts);

    jval_t *tot = j_obj();
    j_set(tot, "bitrate", j_int(total_br));
    j_set(tot, "cc_errors", j_int(ch ? (int64_t)ch->cc_err : 0));
    j_set(tot, "pes_errors", j_int(ch ? (int64_t)ch->pes_err : 0));
    j_set(tot, "scrambled", j_bool(ch ? ch->scrambled : 0));
    jval_t *dt = j_obj();
    j_set(dt, "analyze", j_bool(1));
    j_set(dt, "total", tot);
    jval_t *m = j_obj();
    j_set(m, "data", dt);
    broadcast_ws("scan", m);
    if (sc->cluster_host[0]) broadcast_cluster_ws(sc->cluster_host, "scan", m);
    j_free(m);
}

void ctl_on_tick_1s(void)
{
    static int tick = 0;
    tick++;
    if (g_now >= g_next_csync && !g_csync)
        cluster_sync_start();

    int any_ws = 0;
    for (front_t *fr = g_fronts; fr; fr = fr->gnext) {
        if (!fr->ev.dead && fr->mode == FR_WS && fr->ws_authed) {
            any_ws = 1;
            break;
        }
    }
    if (!any_ws)
        return;

    if (tick % 10 == 0) {
        jval_t *p = j_obj();
        j_set(p, "scope", j_str("ping"));
        char *pt = j_print(p, 0);
        j_free(p);
        if (pt) {
            size_t pl = strlen(pt);
            for (front_t *fr = g_fronts, *nx; fr; fr = nx) {
                nx = fr->gnext;
                if (!fr->ev.dead && fr->mode == FR_WS && fr->ws_authed)
                    ws_send_text(fr, pt, pl);
            }
            free(pt);
        }
    }

    for (int i = 0; i < MAX_SCANS; i++)
        if (g_scans[i].active)
            emit_scan_for(&g_scans[i]);

    for (channel_t *ch = g_channels; ch; ch = ch->next) {
        if (ch->mode == IN_IDLE) {
            ctl_on_ch_idle(ch);
            continue;
        }
        int br_kbps = ch->bitrate > 0 ? (int)(ch->bitrate / 1000.0 + 0.5) : 0;
        int onair = br_kbps > 0;
        if (!onair && ch->input_errors == 0 && !ch->was_active_ws)
            continue;
        ch->was_active_ws = 1;
        uint64_t cc_d = ch->cc_err >= ch->prev_cc_stat ? ch->cc_err - ch->prev_cc_stat : ch->cc_err;
        uint64_t pes_d = ch->pes_err >= ch->prev_pes_stat ? ch->pes_err - ch->prev_pes_stat : ch->pes_err;
        ch->prev_cc_stat = ch->cc_err;
        ch->prev_pes_stat = ch->pes_err;

        jval_t *ev = j_obj();
        j_set(ev, "running", j_bool(1));
        j_set(ev, "idle", j_bool(0));
        j_set(ev, "bitrate", j_int(br_kbps));
        j_set(ev, "effective_bitrate", j_int(br_kbps));
        j_set(ev, "average_bitrate", j_int(br_kbps));
        j_set(ev, "continuity_errors", j_int((int64_t)ch->cc_err));
        j_set(ev, "cc_errors", j_int((int64_t)ch->cc_err));
        j_set(ev, "pes_errors", j_int((int64_t)ch->pes_err));
        j_set(ev, "cc_error", j_int((int64_t)cc_d));
        j_set(ev, "pes_error", j_int((int64_t)pes_d));
        j_set(ev, "scrambled", j_bool(ch->scrambled));
        j_set(ev, "input_id", j_int(ch->cur + 1));
        j_set(ev, "packets", j_int((int64_t)ch->packets));
        j_set(ev, "bytes", j_int((int64_t)(ch->packets * TS)));
        j_set(ev, "input_errors", j_int((int64_t)ch->input_errors));
        j_set(ev, "last_error", ch->last_error[0] ? j_str(ch->last_error) : j_null());
        j_set(ev, "elapsed", j_num(g_now - ch->in_started));
        j_set(ev, "subscribers", j_int(ch->nclients));
        j_set(ev, "channel_id", j_str(ch->id));
        j_set(ev, "onair", j_bool(onair));
        j_set(ev, "sessions", j_int(ch->nclients));

        broadcast_ws("stream_event", ev);
        if (ch->is_cluster && ch->cluster_host[0]) {
            j_set(ev, "channel_id", j_str(ch->cluster_orig_id));
            broadcast_cluster_ws(ch->cluster_host, "stream_event", ev);
        }
        j_free(ev);
    }
}

void ctl_on_sighup(void)
{
    char err[256] = "";
    jval_t *d = load_disk_config(err, sizeof err);
    if (d) {
        apply_config(d, 0, 0, err, sizeof err);
        j_free(d);
        add_log("info", "Configuration reloaded via SIGHUP");
    }
}

/* ----------------------------------------------------------- UI asset serve */

static int gunzip_blob(const uint8_t *gz, size_t gzlen, buf_t *out)
{
    if (out->len > 0)
        return 0;
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK)
        return -1;
    zs.next_in = (Bytef *)gz;
    zs.avail_in = (uInt)gzlen;
    uint8_t tmp[32768];
    int ret;
    do {
        zs.next_out = tmp;
        zs.avail_out = sizeof tmp;
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&zs);
            buf_free(out);
            return -1;
        }
        size_t have = sizeof tmp - zs.avail_out;
        if (have && buf_add(out, tmp, have)) {
            inflateEnd(&zs);
            buf_free(out);
            return -1;
        }
    } while (ret != Z_STREAM_END);
    inflateEnd(&zs);
    return 0;
}

static void serve_ui_gz(front_t *fr, const req_t *r, const uint8_t *gz, size_t gzlen,
                        buf_t *plain_cache, const char *ctype, const char *extra_hdrs)
{
    int head_only = !strcasecmp(r->method, "HEAD");
    if (r->accept_gzip) {
        char hdrs[512];
        snprintf(hdrs, sizeof hdrs, "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n%s",
                 extra_hdrs ? extra_hdrs : "");
        front_respond(fr, 200, "OK", ctype, hdrs, gz, gzlen, NULL, head_only);
        return;
    }
    if (gunzip_blob(gz, gzlen, plain_cache) < 0) {
        front_error(fr, 500, "Decompression failed");
        return;
    }
    front_respond(fr, 200, "OK", ctype, extra_hdrs, plain_cache->p, plain_cache->len, NULL, head_only);
}

/* ----------------------------------------------------------- playlists & output paths */

static void playlist_base_url(const req_t *r, char *out, size_t outsz)
{
    const jval_t *settings = j_get(g_cfg, "settings");
    const char *proto = "http";
    (void)settings;
    char host_hdr[256];
    if (r->host[0])
        snprintf(host_hdr, sizeof host_hdr, "%s", r->host);
    else
        snprintf(host_hdr, sizeof host_hdr, "127.0.0.1:%d", g_port);

    int cport = (int)j_get_int(settings, "http_play_port", 0);
    if (j_is_str(j_get(settings, "http_play_port")))
        cport = atoi(j_get_str(settings, "http_play_port", "0"));
    if (cport > 0) {
        char hname[256];
        size_t hl = strcspn(host_hdr, ":");
        snprintf(hname, sizeof hname, "%.*s", (int)hl, host_hdr);
        snprintf(out, outsz, "%s://%s:%d", proto, hname, cport);
    } else {
        snprintf(out, outsz, "%s://%s", proto, host_hdr);
    }
}

static void serve_m3u_playlist(front_t *fr, const req_t *r)
{
    auth_res_t ar = require_media_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    if (query_has(r->query, "udp")) {
        send_detail(fr, 501, "Not Implemented", "UDP playlist discovery is not supported", NULL);
        return;
    }
    const jval_t *settings = j_get(g_cfg, "settings");
    const char *hdr_extra = j_get_str(settings, "http_play_m3u_header", "");
    const char *arrange = j_get_str(settings, "playlist_arrange", "");
    int use_hls = query_has(r->query, "hls") ||
                  (!query_has(r->query, "ts") && j_get_bool(settings, "http_play_hls", 0) &&
                   !j_get_bool(settings, "http_play_stream", 1));
    int use_ts = query_has(r->query, "ts");
    char token[256] = "";
    query_get(r->query, "token", token, sizeof token);
    char tqs[300] = "";
    if (token[0])
        snprintf(tqs, sizeof tqs, "?token=%s", token);

    char base[384];
    playlist_base_url(r, base, sizeof base);

    buf_t b = {0};
    if (*hdr_extra)
        buf_fmt(&b, "#EXTM3U %s\n", hdr_extra);
    else
        buf_str(&b, "#EXTM3U\n");

    const char *suffix = use_hls ? ".m3u8" : (use_ts ? ".ts" : "");

    const jval_t *lists[2] = {j_get(g_cfg, "make_stream"), NULL};
    for (int pass = 0; pass < 2; pass++) {
        int count = pass == 0 ? j_arr_len(lists[0]) : g_ncstreams;
        for (int i = 0; i < count; i++) {
            const jval_t *s = pass == 0 ? j_arr_get(lists[0], i) : g_cstreams[i].cfg;
            if (!j_is_obj(s) || !j_get_bool(s, "enable", 1))
                continue;
            const char *sid = j_get_str(s, "id", "");
            const char *name = j_get_str(s, "name", sid);
            if (!*name) name = sid;
            const char *tvg = j_get_str(s, "xmltv_id", sid);
            const char *grp = "";
            const jval_t *groups = j_get(s, "groups");
            if (j_is_obj(groups) && groups->child) {
                if (*arrange && j_is_str(j_get(groups, arrange)))
                    grp = j_get_str(groups, arrange, "");
                else if (j_is_str(groups->child))
                    grp = groups->child->str;
            }
            if (*grp)
                buf_fmt(&b, "#EXTINF:-1 tvg-id=\"%s\" group-title=\"%s\",%s\n", tvg, grp, name);
            else
                buf_fmt(&b, "#EXTINF:-1 tvg-id=\"%s\",%s\n", tvg, name);
            buf_fmt(&b, "%s/play/%s%s%s\n", base, sid, suffix, tqs);
        }
    }
    front_respond(fr, 200, "OK", "audio/x-mpegurl", "Cache-Control: no-store\r\n",
                  b.p, b.len, NULL, !strcasecmp(r->method, "HEAD"));
    buf_free(&b);
}

static void serve_xspf_playlist(front_t *fr, const req_t *r)
{
    auth_res_t ar = require_media_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    const jval_t *settings = j_get(g_cfg, "settings");
    const char *title = j_get_str(settings, "http_play_xspf_title", "AstraG IPTV Playlist");
    char token[256] = "";
    query_get(r->query, "token", token, sizeof token);
    char tqs[300] = "";
    if (token[0])
        snprintf(tqs, sizeof tqs, "?token=%s", token);
    char base[384];
    playlist_base_url(r, base, sizeof base);

    buf_t b = {0};
    buf_str(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<playlist xmlns=\"http://xspf.org/ns/0/\" version=\"1\">\n  <title>");
    xml_escape_buf(&b, title);
    buf_str(&b, "</title>\n  <trackList>\n");

    const jval_t *ms = j_get(g_cfg, "make_stream");
    for (int pass = 0; pass < 2; pass++) {
        int count = pass == 0 ? j_arr_len(ms) : g_ncstreams;
        for (int i = 0; i < count; i++) {
            const jval_t *s = pass == 0 ? j_arr_get(ms, i) : g_cstreams[i].cfg;
            if (!j_is_obj(s) || !j_get_bool(s, "enable", 1))
                continue;
            const char *sid = j_get_str(s, "id", "");
            const char *name = j_get_str(s, "name", sid);
            if (!*name) name = sid;
            char loc[1024];
            snprintf(loc, sizeof loc, "%s/play/%s%s", base, sid, tqs);
            buf_str(&b, "    <track><title>");
            xml_escape_buf(&b, name);
            buf_str(&b, "</title><location>");
            xml_escape_buf(&b, loc);
            buf_str(&b, "</location></track>\n");
        }
    }
    buf_str(&b, "  </trackList>\n</playlist>\n");
    front_respond(fr, 200, "OK", "application/xspf+xml", "Cache-Control: no-store\r\n",
                  b.p, b.len, NULL, !strcasecmp(r->method, "HEAD"));
    buf_free(&b);
}

static int is_reserved_ui_path(const char *p)
{
    static const char *pref[] = {"/control", "/api", "/account", "/__health", "/mod.js", "/favicon.", "/index.html"};
    if (!strcmp(p, "/"))
        return 1;
    for (size_t i = 0; i < sizeof pref / sizeof pref[0]; i++) {
        size_t l = strlen(pref[i]);
        if (!strcmp(p, pref[i]) || (!strncmp(p, pref[i], l) && p[l] == '/') ||
            (!strcmp(pref[i], "/favicon.") && !strncmp(p, "/favicon.", 9)))
            return 1;
    }
    return 0;
}

static int resolve_http_output(const char *path, int req_port, char *sid_out, size_t ssz,
                               int *mode_out, char *seg_out, size_t segsz)
{
    /* mode_out: 0 = ts, 1 = hls, 2 = segment */
    char req_path[2048];
    const char *p = path ? path : "/";
    while (*p == '/') p++;
    snprintf(req_path, sizeof req_path, "/%s", p);
    size_t rpl = strlen(req_path);
    while (rpl > 1 && req_path[rpl - 1] == '/') req_path[--rpl] = 0;
    if (is_reserved_ui_path(req_path))
        return 0;

    int found = 0;
    int fb_mode = 0;
    char fb_sid[128] = "", fb_seg[256] = "";

    const jval_t *ms = j_get(g_cfg, "make_stream");
    for (int pass = 0; pass < 2; pass++) {
        int count = pass == 0 ? j_arr_len(ms) : g_ncstreams;
        for (int i = 0; i < count; i++) {
            const jval_t *s = pass == 0 ? j_arr_get(ms, i) : g_cstreams[i].cfg;
            if (!j_is_obj(s) || !j_get_bool(s, "enable", 1))
                continue;
            const char *sid = j_get_str(s, "id", "");
            const jval_t *outs = j_get(s, "output");
            if (!j_is_arr(outs))
                continue;
            for (jval_t *it = outs->child; it; it = it->next) {
                if (!j_is_str(it))
                    continue;
                int https = 0, out_port = -1;
                const char *u = it->str;
                if (!strncasecmp(u, "http://", 7)) u += 7;
                else if (!strncasecmp(u, "https://", 8)) { https = 1; u += 8; }
                else continue;
                (void)https;
                const char *end = u + strcspn(u, "/?#");
                const char *at = memrchr(u, '@', (size_t)(end - u));
                const char *hp = at ? at + 1 : u;
                const char *col = memchr(hp, ':', (size_t)(end - hp));
                if (col) out_port = atoi(col + 1);
                size_t opl_raw = strcspn(end, "#?");
                char out_path[1024];
                const char *op = end;
                while (*op == '/' && (size_t)(op - end) < opl_raw) op++;
                size_t rem = opl_raw - (size_t)(op - end);
                snprintf(out_path, sizeof out_path, "/%.*s", (int)rem, op);
                size_t opl = strlen(out_path);
                while (opl > 1 && out_path[opl - 1] == '/') out_path[--opl] = 0;
                if (!strcmp(out_path, "/"))
                    continue;

                char base_path[1024];
                int cfg_hls = 0;
                if (opl > 11 && !strcmp(out_path + opl - 11, "/index.m3u8")) {
                    snprintf(base_path, sizeof base_path, "%.*s", (int)(opl - 11), out_path);
                    cfg_hls = 1;
                } else if (opl > 5 && !strcmp(out_path + opl - 5, ".m3u8")) {
                    snprintf(base_path, sizeof base_path, "%.*s", (int)(opl - 5), out_path);
                    cfg_hls = 1;
                } else if (opl > 3 && !strcmp(out_path + opl - 3, ".ts")) {
                    snprintf(base_path, sizeof base_path, "%.*s", (int)(opl - 3), out_path);
                } else {
                    snprintf(base_path, sizeof base_path, "%s", out_path);
                }
                if (!base_path[0]) strcpy(base_path, "/");
                size_t bpl = strlen(base_path);

                int m = -1;
                char sg[256] = "";
                if (!strcmp(req_path, out_path)) {
                    m = cfg_hls ? 1 : 0;
                } else if (strcmp(base_path, "/") != 0) {
                    if (!strcmp(req_path, base_path) ||
                        (!strncmp(req_path, base_path, bpl) && !strcmp(req_path + bpl, ".ts"))) {
                        m = 0;
                    } else if (!strncmp(req_path, base_path, bpl) &&
                               (!strcmp(req_path + bpl, ".m3u8") || !strcmp(req_path + bpl, "/index.m3u8"))) {
                        m = 1;
                    } else if (!strncmp(req_path, base_path, bpl) &&
                               !strncmp(req_path + bpl, "/segment/", 9) && req_path[bpl + 9]) {
                        m = 2;
                        snprintf(sg, sizeof sg, "%s", req_path + bpl + 9);
                    } else if (!strncmp(req_path, base_path, bpl) && req_path[bpl] == '/' &&
                               rpl > 3 && !strcmp(req_path + rpl - 3, ".ts")) {
                        const char *last_sl = strrchr(req_path, '/');
                        if (last_sl && !strncmp(last_sl + 1, "segment-", 8)) {
                            m = 2;
                            snprintf(sg, sizeof sg, "%s", last_sl + 1);
                        }
                    }
                }
                if (m >= 0) {
                    if (out_port == req_port) {
                        snprintf(sid_out, ssz, "%s", sid);
                        *mode_out = m;
                        snprintf(seg_out, segsz, "%s", sg);
                        return 1;
                    }
                    if (!found) {
                        found = 1;
                        snprintf(fb_sid, sizeof fb_sid, "%s", sid);
                        fb_mode = m;
                        snprintf(fb_seg, sizeof fb_seg, "%s", sg);
                    }
                }
            }
        }
    }
    if (found) {
        snprintf(sid_out, ssz, "%s", fb_sid);
        *mode_out = fb_mode;
        snprintf(seg_out, segsz, "%s", fb_seg);
        return 1;
    }
    return 0;
}

static void handle_media_play_ts(front_t *fr, const req_t *r, const char *sid, const char *host_hint)
{
    auth_res_t ar = require_media_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    const char *rsid = resolve_stream_id(sid, host_hint);
    if (!rsid) {
        front_error(fr, 404, "Stream not found");
        return;
    }
    channel_t *ch = ensure_channel_started(rsid);
    if (!ch) {
        front_error(fr, 409, "Stream disabled or has no input");
        return;
    }
    if (!strcasecmp(r->method, "HEAD")) {
        front_respond(fr, 200, "OK", "video/mp2t", "Cache-Control: no-store\r\nAccept-Ranges: none\r\n",
                      NULL, 0, NULL, 1);
        return;
    }
    ch_serve_ts(fr, ch, ar.login);
}

static void handle_media_play_hls(front_t *fr, const req_t *r, const char *sid, const char *host_hint)
{
    auth_res_t ar = require_media_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    const char *rsid = resolve_stream_id(sid, host_hint);
    if (!rsid) {
        front_error(fr, 404, "Stream not found");
        return;
    }
    channel_t *ch = ensure_channel_started(rsid);
    if (!ch) {
        front_error(fr, 409, "Stream disabled or has no input");
        return;
    }
    if (query_has(r->query, "udp")) {
        front_error(fr, 501, "UDP playlist discovery is not supported");
        return;
    }
    char token[256] = "", tqs[300] = "";
    if (query_get(r->query, "token", token, sizeof token) && token[0])
        snprintf(tqs, sizeof tqs, "?token=%s", token);
    if (query_has(r->query, "ts")) {
        char body[512];
        snprintf(body, sizeof body, "#EXTM3U\n/play/%s%s\n", rsid, tqs);
        front_respond(fr, 200, "OK", "audio/x-mpegurl", NULL, body, strlen(body), NULL, 0);
        return;
    }
    char pre[512];
    snprintf(pre, sizeof pre, "/play/%s/segment/", rsid);
    ch_serve_hls(fr, ch, pre, tqs, !strcasecmp(r->method, "HEAD"));
}

static void handle_media_play_seg(front_t *fr, const req_t *r, const char *sid, const char *seg_name, const char *host_hint)
{
    auth_res_t ar = require_media_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    const char *rsid = resolve_stream_id(sid, host_hint);
    if (!rsid) {
        front_error(fr, 404, "Stream not found");
        return;
    }
    channel_t *ch = ensure_channel_started(rsid);
    if (!ch) {
        front_error(fr, 409, "Stream disabled or has no input");
        return;
    }
    ch_serve_seg(fr, ch, seg_name, !strcasecmp(r->method, "HEAD"));
}

/* ----------------------------------------------------------- control API */

static void handle_control_api(front_t *fr, const req_t *r)
{
    auth_res_t ar = require_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden",
                    ar.detail, ar.status == 429 ? "Retry-After: 60\r\n" : NULL);
        return;
    }
    jval_t *body = j_parse_n((const char *)r->body, r->body_len);
    if (!j_is_obj(body)) {
        j_free(body);
        send_detail(fr, j_is_arr(body) ? 422 : 400, "Bad Request", "Invalid JSON", NULL);
        return;
    }
    const char *cmd_raw = j_get_str(body, "cmd", NULL);
    if (!cmd_raw) {
        j_free(body);
        send_detail(fr, 422, "Unprocessable Entity", "cmd must be a string", NULL);
        return;
    }
    char cmd_buf[64];
    snprintf(cmd_buf, sizeof cmd_buf, "%s", cmd_raw);
    const char *cmd = cmd_buf;

    if (!strcmp(cmd, "version")) {
        j_free(body);
        jval_t *v = j_obj();
        j_set(v, "version", j_str(ASTRAG_VERSION));
        j_set(v, "commit", j_str("astrag-c"));
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }
    if (!strcmp(cmd, "status")) {
        j_free(body);
        int scount = 0;
        for (channel_t *ch = g_channels; ch; ch = ch->next) scount += ch->nclients;
        jval_t *sys = j_obj();
        j_set(sys, "cpu_frequency_max", j_int(0));
        j_set(sys, "cpu_frequency_cur", j_int(0));
        jval_t *v = j_obj();
        j_set(v, "version", j_str(ASTRAG_VERSION));
        j_set(v, "commit", j_str("astrag-c"));
        j_set(v, "uptime", j_int((int64_t)(time(NULL) - g_started_wall)));
        j_set(v, "observer", j_bool(!ar.admin));
        j_set(v, "dvb_list", j_arr());
        j_set(v, "net_list", j_arr());
        j_set(v, "sessions_count", j_int(scount));
        j_set(v, "system", sys);
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }
    if (!strcmp(cmd, "load")) {
        j_free(body);
        if (ar.admin)
            send_json(fr, 200, "OK", g_cfg, NULL);
        else {
            jval_t *red = redact_val(g_cfg, 1);
            send_json(fr, 200, "OK", red, NULL);
            j_free(red);
        }
        return;
    }
    if (!strcmp(cmd, "sessions")) {
        j_free(body);
        jval_t *arr = j_arr();
        time_t noww = time(NULL);
        for (channel_t *ch = g_channels; ch; ch = ch->next) {
            for (front_t *c = ch->clients; c; c = c->cnext) {
                jval_t *so = j_obj();
                j_set(so, "client_id", j_int((int64_t)c->sess));
                j_set(so, "channel_id", j_str(ch->id));
                j_set(so, "channel_name", j_str(ch->name));
                j_set(so, "addr", j_str(c->ip));
                j_set(so, "login", j_str(c->login));
                j_set(so, "ua", j_str(c->ua));
                j_set(so, "sdate", j_int(c->sess_sdate_ms));
                j_set(so, "uptime", j_int((int64_t)(noww - c->sess_start_wall)));
                j_arr_add(arr, so);
            }
        }
        jval_t *v = j_obj();
        j_set(v, "sessions", arr);
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }
    if (!strcmp(cmd, "log")) {
        j_free(body);
        jval_t *arr = j_arr();
        for (int i = 0; i < g_log_cnt; i++) {
            jval_t *le = j_obj();
            j_set(le, "type", j_str(g_logs[i].type));
            j_set(le, "time", j_int((int64_t)g_logs[i].ts));
            j_set(le, "text", j_str(g_logs[i].text));
            j_arr_add(arr, le);
        }
        jval_t *v = j_obj();
        j_set(v, "log", arr);
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }

    if (!ar.admin) {
        j_free(body);
        send_detail(fr, 403, "Forbidden", "Administrator role required", NULL);
        return;
    }

    if (!strcmp(cmd, "scan-init")) {
        const char *st = j_get_str(body, "scan", "");
        if (!strncmp(st, "stream://", 9)) {
            char sid_hex[16];
            gen_uuid_hex(sid_hex, sizeof sid_hex, 5);
            for (int i = 0; i < MAX_SCANS; i++) {
                if (!g_scans[i].active) {
                    g_scans[i].active = 1;
                    snprintf(g_scans[i].id, sizeof g_scans[i].id, "%s", sid_hex);
                    snprintf(g_scans[i].stream_id, sizeof g_scans[i].stream_id, "%s", st + 9);
                    g_scans[i].cluster_host[0] = 0;
                    break;
                }
            }
            j_free(body);
            jval_t *v = j_obj();
            j_set(v, "scan-init", j_str("ok"));
            j_set(v, "id", j_str(sid_hex));
            send_json(fr, 200, "OK", v, NULL);
            j_free(v);
            return;
        }
        j_free(body);
        send_detail(fr, 501, "Not Implemented", "DVB hardware operations are not implemented", NULL);
        return;
    }
    if (!strcmp(cmd, "scan-kill")) {
        const char *id = j_get_str(body, "id", "");
        for (int i = 0; i < MAX_SCANS; i++)
            if (g_scans[i].active && !strcmp(g_scans[i].id, id))
                g_scans[i].active = 0;
        j_free(body);
        jval_t *v = j_obj();
        j_set(v, "scan-kill", j_str("ok"));
        j_set(v, "success", j_bool(1));
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }
    if (!strncmp(cmd, "scan-", 5) || !strcmp(cmd, "restart-adapter")) {
        j_free(body);
        send_detail(fr, 501, "Not Implemented", "DVB hardware operations are not implemented", NULL);
        return;
    }
    if (!strcmp(cmd, "close-session")) {
        const jval_t *vid = j_get(body, "id");
        if (!j_is_num(vid)) {
            j_free(body);
            send_detail(fr, 422, "Unprocessable Entity", "id must be an integer", NULL);
            return;
        }
        uint64_t target_id = (uint64_t)vid->inum;
        j_free(body);
        int closed = 0;
        for (channel_t *ch = g_channels; ch && !closed; ch = ch->next) {
            for (front_t *c = ch->clients; c; c = c->cnext) {
                if (c->sess == target_id) {
                    front_close(c);
                    closed = 1;
                    break;
                }
            }
        }
        if (!closed) {
            send_detail(fr, 404, "Not Found", "Session not found", NULL);
            return;
        }
        jval_t *v = j_obj();
        j_set(v, "success", j_bool(1));
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }
    if (!strcmp(cmd, "restart")) {
        j_free(body);
        char err[256] = "";
        jval_t *d = load_disk_config(err, sizeof err);
        if (!d || apply_config(d, 0, 1, err, sizeof err) < 0) {
            j_free(d);
            send_detail(fr, 500, "Error", err[0] ? err : "Reload failed", NULL);
            return;
        }
        j_free(d);
        add_log("info", "Configuration and streams reloaded");
        jval_t *v = j_obj();
        j_set(v, "success", j_bool(1));
        j_set(v, "message", j_str("Configuration and engines reloaded; process not restarted"));
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }

    jval_t *config = j_dup(g_cfg);
    jval_t *event = j_obj();
    jval_t *result = j_obj();
    j_set(result, "success", j_bool(1));
    char ws_scope[64];
    snprintf(ws_scope, sizeof ws_scope, "%s", cmd);
    int close_revoked = 0;
    char revoke_logins[2][96];
    int nrevoke = 0;

    if (!strcmp(cmd, "upload")) {
        const jval_t *up = j_get(body, "config");
        if (!j_is_obj(up)) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "config must be an object", NULL);
            return;
        }
        jval_t *uploaded = j_dup(up);
        jval_t *uusers = j_get(uploaded, "users");
        const jval_t *cur_users = j_get(config, "users");
        if (j_is_obj(uusers) && j_is_obj(cur_users)) {
            for (jval_t *ud = uusers->child; ud; ud = ud->next) {
                if (j_is_obj(ud) && ud->key && !j_get_str(ud, "password", "")[0]) {
                    const jval_t *old_u = j_get(cur_users, ud->key);
                    const char *old_pw = j_get_str(old_u, "password", NULL);
                    if (old_pw && *old_pw)
                        j_set(ud, "password", j_str(old_pw));
                }
            }
        }
        j_free(config);
        config = uploaded;
        j_set(event, "reload", j_bool(1));
    } else if (!strcmp(cmd, "set-stream")) {
        const jval_t *sp = j_get(body, "stream");
        if (!j_is_obj(sp)) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "stream must be an object", NULL);
            return;
        }
        jval_t *data = j_dup(sp);
        const char *req_id = j_get_str(body, "id", "");
        const char *dat_id = j_get_str(data, "id", "");
        int is_rem = j_get_bool(data, "remove", j_get_bool(body, "remove", 0));
        char sid[128] = "", old_sid[128] = "";
        const char *chosen = is_rem ? ((*req_id && strcmp(req_id, "-")) ? req_id : dat_id)
                                    : ((*dat_id && strcmp(dat_id, "-")) ? dat_id : req_id);
        if (!*chosen || !strcmp(chosen, "-"))
            gen_uuid_hex(sid, sizeof sid, 6);
        else
            snprintf(sid, sizeof sid, "%s", chosen);
        snprintf(old_sid, sizeof old_sid, "%s", (*req_id && strcmp(req_id, "-")) ? req_id : sid);
        j_set(data, "id", j_str(sid));

        jval_t *ms = j_get(config, "make_stream");
        jval_t *nms = j_arr();
        for (jval_t *s = ms->child; s; s = s->next) {
            const char *cid = j_get_str(s, "id", "");
            if (strcmp(cid, sid) != 0 && strcmp(cid, old_sid) != 0)
                j_arr_add(nms, j_dup(s));
        }
        if (!is_rem) {
            j_arr_add(nms, j_dup(data));
            add_log("info", "Stream '%s' (%s) saved", j_get_str(data, "name", sid), sid);
        } else {
            j_set(data, "remove", j_bool(1));
            add_log("warning", "Stream '%s' removed", sid);
        }
        j_set(config, "make_stream", nms);
        j_set(event, "id", j_str(old_sid));
        j_set(event, "stream", data);
        j_set(result, "id", j_str(sid));
    } else if (!strcmp(cmd, "set-stream-input")) {
        const char *sid = j_get_str(body, "id", "");
        jval_t *ms = j_get(config, "make_stream");
        jval_t *stream = NULL;
        for (jval_t *s = ms->child; s; s = s->next)
            if (!strcmp(j_get_str(s, "id", ""), sid)) { stream = s; break; }
        if (!stream) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 404, "Not Found", "Stream not found", NULL);
            return;
        }
        if (j_get(body, "input")) {
            j_set(stream, "input", j_dup(j_get(body, "input")));
        } else {
            jval_t *ins = j_get(stream, "input");
            if (j_arr_len(ins) > 1) {
                jval_t *first = j_dup(ins->child);
                j_arr_del(ins, 0);
                j_arr_add(ins, first);
            } else {
                j_free(body); j_free(config); j_free(event); j_free(result);
                send_detail(fr, 409, "Conflict", "No alternate input configured", NULL);
                return;
            }
        }
        j_set(event, "channel_id", j_str(sid));
        j_set(event, "input_id", j_int(1));
        snprintf(ws_scope, sizeof ws_scope, "stream_event");
    } else if (!strcmp(cmd, "set-user")) {
        const jval_t *up = j_get(body, "user");
        const char *sid_raw = j_get_str(body, "id", NULL);
        if (!j_is_obj(up) || !sid_raw || !*sid_raw) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "id must be a nonempty login", NULL);
            return;
        }
        char sid[96], old_id[96] = "";
        snprintf(sid, sizeof sid, "%s", sid_raw);
        const char *oi = j_get_str(body, "old_id", NULL);
        if (oi) snprintf(old_id, sizeof old_id, "%s", oi);

        jval_t *users = j_get(config, "users");
        jval_t *data = j_dup(up);
        int is_rem = j_get_bool(data, "remove", j_get_bool(body, "remove", 0));
        if (is_rem) {
            j_del(users, sid);
            snprintf(revoke_logins[nrevoke++], 96, "%s", sid);
            if (old_id[0] && strcmp(old_id, sid) != 0) {
                j_del(users, old_id);
                snprintf(revoke_logins[nrevoke++], 96, "%s", old_id);
            }
            close_revoked = 1;
            j_set(data, "remove", j_bool(1));
        } else {
            if (old_id[0] && strcmp(old_id, sid) != 0 && j_get(users, sid)) {
                j_free(body); j_free(config); j_free(event); j_free(result); j_free(data);
                send_detail(fr, 409, "Conflict", "Login is already in use", NULL);
                return;
            }
            const char *target_key = (old_id[0] && j_get(users, old_id)) ? old_id : sid;
            const jval_t *existing = j_get(users, target_key);
            jval_t *merged = existing ? j_dup(existing) : j_obj();
            for (jval_t *c = data->child; c; c = c->next)
                if (c->key) j_set(merged, c->key, j_dup(c));
            const char *raw_pw = j_get_str(data, "password", "");
            if (*raw_pw) {
                j_set(merged, "password", j_str(raw_pw));
                j_del(merged, "firstrun");
            } else if (existing && j_get_str(existing, "password", NULL)) {
                j_set(merged, "password", j_str(j_get_str(existing, "password", "admin")));
            } else {
                j_set(merged, "password", j_str("admin"));
            }
            int utype = (int)j_get_int(merged, "type", !strcmp(j_get_str(merged, "role", ""), "admin") ? 1 : 3);
            if (utype == 1 || !strcmp(j_get_str(merged, "role", ""), "admin")) {
                j_set(merged, "role", j_str("admin"));
                j_set(merged, "type", j_int(1));
            } else {
                j_set(merged, "type", j_int(utype));
                j_del(merged, "role");
            }
            if (!j_get(merged, "enable"))
                j_set(merged, "enable", j_bool(1));
            else
                j_set(merged, "enable", j_bool(j_get_bool(merged, "enable", 1)));
            if (!j_get(merged, "created"))
                j_set(merged, "created", j_int((int64_t)time(NULL)));
            if (old_id[0] && strcmp(old_id, sid) != 0) {
                j_del(users, old_id);
                snprintf(revoke_logins[nrevoke++], 96, "%s", old_id);
                close_revoked = 1;
            }
            j_set(users, sid, merged);
            j_free(data);
            data = j_dup(merged);
        }
        j_set(event, "id", j_str(sid));
        j_set(event, "user", data);
        if (old_id[0] && strcmp(old_id, sid) != 0)
            j_set(event, "old_id", j_str(old_id));
    } else if (!strcmp(cmd, "set-settings") || !strcmp(cmd, "set-auth")) {
        const char *key = cmd + 4;
        const jval_t *p = j_get(body, key);
        jval_t *data = j_is_obj(p) ? j_dup(p) : (!strcmp(key, "auth") ? j_obj() : NULL);
        if (!data) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "payload must be an object", NULL);
            return;
        }
        if (j_get_bool(data, "remove", 0)) {
            j_free(data);
            data = j_obj();
        }
        j_set(config, key, data);
        j_set(event, key, j_dup(data));
    } else if (!strcmp(cmd, "set-log")) {
        const jval_t *p = j_get(body, "set");
        jval_t *data = j_is_obj(p) ? j_dup(p) : j_obj();
        j_set(config, "log", data);
        j_set(event, "set", j_dup(data));
        snprintf(ws_scope, sizeof ws_scope, "log_event");
    } else if (!strcmp(cmd, "set-config")) {
        const char *key = j_get_str(body, "key", "");
        if (!*key) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "key required", NULL);
            return;
        }
        const jval_t *dp = j_get(body, "data");
        int rem = j_get_bool(body, "remove", 0) || (j_is_obj(dp) && j_get_bool(dp, "remove", 0));
        if (rem) {
            j_del(config, key);
            j_set(event, "key", j_str(key));
            j_set(event, "data", j_null());
        } else {
            jval_t *d = dp ? j_dup(dp) : j_obj();
            j_set(config, key, j_dup(d));
            j_set(event, "key", j_str(key));
            j_set(event, "data", d);
        }
    } else if (!strcmp(cmd, "set-category") || !strcmp(cmd, "set-server") ||
               !strcmp(cmd, "set-softcam") || !strcmp(cmd, "set-cas") || !strcmp(cmd, "set-adapter")) {
        const char *name = cmd + 4;
        const char *ckey = !strcmp(name, "category") ? "categories" :
                           !strcmp(name, "server") ? "servers" :
                           !strcmp(name, "adapter") ? "dvb_tune" : name;
        const jval_t *dp = j_get(body, name);
        if (!j_is_obj(dp)) {
            j_free(body); j_free(config); j_free(event); j_free(result);
            send_detail(fr, 422, "Unprocessable Entity", "entry must be an object", NULL);
            return;
        }
        jval_t *data = j_dup(dp);
        jval_t *values = j_get(config, ckey);
        const jval_t *idv = j_get(body, "id") ?: j_get(data, "id");
        if (!strcmp(name, "category") || !strcmp(name, "server")) {
            int have_idx = idv && (j_is_num(idv) || (j_is_str(idv) && strcmp(idv->str, "-") != 0 && *idv->str));
            if (have_idx) {
                int idx = j_is_num(idv) ? (int)idv->inum : atoi(idv->str);
                if (idx < 0 || idx >= j_arr_len(values)) {
                    j_free(body); j_free(config); j_free(event); j_free(result); j_free(data);
                    send_detail(fr, 404, "Not Found", "Entry not found", NULL);
                    return;
                }
                if (j_get_bool(data, "remove", j_get_bool(body, "remove", 0))) {
                    j_set(data, "remove", j_bool(1));
                    j_arr_del(values, idx);
                } else {
                    jval_t *narr = j_arr();
                    int n = j_arr_len(values);
                    for (int i = 0; i < n; i++)
                        j_arr_add(narr, i == idx ? j_dup(data) : j_dup(j_arr_get(values, i)));
                    j_set(config, ckey, narr);
                }
                j_set(event, "id", j_int(idx));
            } else if (j_get_bool(data, "remove", 0)) {
                j_free(body); j_free(config); j_free(event); j_free(result); j_free(data);
                send_detail(fr, 422, "Unprocessable Entity", "Removal requires id", NULL);
                return;
            } else {
                j_arr_add(values, j_dup(data));
            }
        } else {
            const char *req_id = j_get_str(body, "id", "");
            const char *dat_id = j_get_str(data, "id", "");
            int is_rem = j_get_bool(data, "remove", j_get_bool(body, "remove", 0));
            char sid[64], old_sid[64];
            const char *ch_id = is_rem ? ((*req_id && strcmp(req_id, "-")) ? req_id : dat_id)
                                       : ((*dat_id && strcmp(dat_id, "-")) ? dat_id : req_id);
            if (!*ch_id || !strcmp(ch_id, "-")) gen_uuid_hex(sid, sizeof sid, 6);
            else snprintf(sid, sizeof sid, "%s", ch_id);
            snprintf(old_sid, sizeof old_sid, "%s", (*req_id && strcmp(req_id, "-")) ? req_id : sid);
            j_set(data, "id", j_str(sid));
            jval_t *narr = j_arr();
            for (jval_t *el = values->child; el; el = el->next) {
                const char *eid = j_get_str(el, "id", "");
                if (strcmp(eid, sid) != 0 && strcmp(eid, old_sid) != 0)
                    j_arr_add(narr, j_dup(el));
            }
            if (is_rem) j_set(data, "remove", j_bool(1));
            else j_arr_add(narr, j_dup(data));
            j_set(config, ckey, narr);
            j_set(event, "id", j_str(old_sid));
            j_set(result, "configuration_only", j_bool(1));
        }
        j_set(event, name, data);
    } else {
        j_free(body); j_free(config); j_free(event); j_free(result);
        send_detail(fr, 400, "Bad Request", "Unknown command", NULL);
        return;
    }

    if (j_is_num(j_get(body, "gid"))) {
        int64_t g = j_get_int(body, "gid", 466560);
        j_set(config, "gid", j_int(g));
        j_set(event, "gid", j_int(g));
    }
    int rebuild = j_get_bool(body, "restart", 0);
    j_free(body);

    char err[256] = "";
    if (apply_config(config, 1, rebuild, err, sizeof err) < 0) {
        j_free(config); j_free(event); j_free(result);
        send_detail(fr, 422, "Unprocessable Entity", err[0] ? err : "Invalid config", NULL);
        return;
    }
    j_free(config);
    broadcast_ws(ws_scope, event);
    j_free(event);
    if (close_revoked)
        for (int i = 0; i < nrevoke; i++)
            revoke_account_sockets(revoke_logins[i]);
    send_json(fr, 200, "OK", result, NULL);
    j_free(result);
}

/* ----------------------------------------------------------- account API */

static int same_origin_ok(const req_t *r)
{
    if (!r->origin[0])
        return 1;
    const char *sc = strstr(r->origin, "://");
    if (!sc)
        return 0;
    const char *hp = sc + 3;
    if (strchr(hp, '@') || strchr(hp, '?') || strchr(hp, '#'))
        return 0;
    const char *sl = strchr(hp, '/');
    if (sl && sl[1] != 0)
        return 0;
    char ohost[256];
    snprintf(ohost, sizeof ohost, "%.*s", sl ? (int)(sl - hp) : (int)strlen(hp), hp);
    return !strcasecmp(ohost, r->host);
}

static void handle_account_change(front_t *fr, const req_t *r)
{
    if (!same_origin_ok(r)) {
        send_detail(fr, 403, "Forbidden", "Cross-origin account changes are forbidden", NULL);
        return;
    }
    auth_res_t ar = require_auth(fr, r);
    if (!ar.ok) {
        send_detail(fr, ar.status, ar.status == 429 ? "Too Many Requests" : "Forbidden", ar.detail, NULL);
        return;
    }
    if (!j_get_bool(j_get(g_cfg, "auth"), "enable", 0) || !ar.login[0]) {
        send_detail(fr, 403, "Forbidden", "Account authentication must be enabled", NULL);
        return;
    }
    jval_t *body = j_parse_n((const char *)r->body, r->body_len);
    if (!j_is_obj(body)) {
        j_free(body);
        send_detail(fr, 400, "Bad Request", "Invalid JSON", NULL);
        return;
    }
    const char *new_login_raw = j_get_str(body, "new_login", "");
    const char *new_pass = j_get_str(body, "new_password", "");
    const char *cur_pass = j_get_str(body, "current_password", "");
    if (!valid_login(new_login_raw) || !valid_password(new_pass)) {
        j_free(body);
        send_detail(fr, 422, "Unprocessable Entity",
                    "Login: 1-64 ASCII letters, digits, _, ., @ or -; password: 12-256 characters with letters and digits",
                    NULL);
        return;
    }
    char new_login[96];
    snprintf(new_login, sizeof new_login, "%s", new_login_raw);
    const jval_t *users = j_get(g_cfg, "users");
    const jval_t *cur = j_get(users, ar.login);
    const char *expected = j_get_str(cur, "password", NULL);
    if (!expected || !*expected) expected = j_get_str(cur, "token", NULL);
    if (!verify_password(cur_pass, expected)) {
        j_free(body);
        auth_limiter_failed(fr->ip);
        send_detail(fr, 403, "Forbidden", "Current password is incorrect", NULL);
        return;
    }
    if (strcmp(new_login, ar.login) != 0 && j_get(users, new_login)) {
        j_free(body);
        send_detail(fr, 409, "Conflict", "Login is already in use", NULL);
        return;
    }
    char hashed[256];
    if (hash_password(new_pass, hashed, sizeof hashed) < 0) {
        j_free(body);
        send_detail(fr, 500, "Error", "Password hashing failed", NULL);
        return;
    }
    jval_t *ncfg = j_dup(g_cfg);
    jval_t *nu = j_get(ncfg, "users");
    jval_t *acc = j_detach(nu, ar.login);
    j_del(acc, "token");
    j_set(acc, "password", j_str(hashed));
    j_set(nu, new_login, acc);
    j_free(body);

    char err[256] = "";
    apply_config(ncfg, 1, 0, err, sizeof err);
    j_free(ncfg);
    revoke_account_sockets(ar.login);

    jval_t *res = j_obj();
    j_set(res, "success", j_bool(1));
    j_set(res, "login", j_str(new_login));
    send_json(fr, 200, "OK", res, NULL);
    j_free(res);
}

static void handle_reset_password(front_t *fr, const req_t *r)
{
    auth_res_t ar = require_auth(fr, r);
    if (!ar.ok || !ar.admin) {
        send_detail(fr, ar.ok ? 403 : ar.status, "Forbidden",
                    ar.ok ? "Administrator role required" : ar.detail, NULL);
        return;
    }
    jval_t *body = j_parse_n((const char *)r->body, r->body_len);
    const char *login_raw = j_get_str(body, "login", NULL);
    const char *pw = j_get_str(body, "password", NULL);
    if (!login_raw || !valid_password(pw)) {
        j_free(body);
        send_detail(fr, 422, "Unprocessable Entity",
                    "Supply login and a password of at least 12 characters with letters and digits", NULL);
        return;
    }
    char login[96];
    snprintf(login, sizeof login, "%s", login_raw);
    if (!j_get(j_get(g_cfg, "users"), login)) {
        j_free(body);
        send_detail(fr, 404, "Not Found", "User not found", NULL);
        return;
    }
    char hashed[256];
    hash_password(pw, hashed, sizeof hashed);
    jval_t *ncfg = j_dup(g_cfg);
    jval_t *u = j_get(j_get(ncfg, "users"), login);
    j_del(u, "token");
    j_set(u, "password", j_str(hashed));
    char err[256] = "";
    apply_config(ncfg, 1, 0, err, sizeof err);
    j_free(ncfg);
    revoke_account_sockets(login);
    j_free(body);

    jval_t *res = j_obj();
    j_set(res, "success", j_bool(1));
    j_set(res, "login", j_str(login));
    send_json(fr, 200, "OK", res, NULL);
    j_free(res);
}

/* ----------------------------------------------------------- cluster HTTP proxy */

typedef struct {
    front_t *fr;
    char target[128];
    char cmd[64];
    buf_t body;
} cfetch_ctx_t;

static void cfetch_head(fetch_t *f) { (void)f; }
static void cfetch_data(fetch_t *f, const uint8_t *d, size_t n)
{
    cfetch_ctx_t *ctx = f->owner;
    if (!ctx || !ctx->fr || ctx->fr->ev.dead)
        return;
    if (ctx->body.len + n < 16u * 1024 * 1024)
        buf_add(&ctx->body, d, n);
}
static void cfetch_done(fetch_t *f, int ok, const char *err)
{
    cfetch_ctx_t *ctx = f->owner;
    if (!ctx)
        return;
    front_t *fr = ctx->fr;
    if (fr && !fr->ev.dead) {
        fr->cfetch = NULL;
        if (ok && f->status > 0) {
            if (f->status == 200 && !strcmp(ctx->cmd, "load") && ctx->body.len > 0) {
                jval_t *p = j_parse_n((const char *)ctx->body.p, ctx->body.len);
                if (j_is_obj(p)) ccache_set(ctx->target, p);
                j_free(p);
            }
            front_respond(fr, f->status, f->status == 200 ? "OK" : "Error",
                          f->ctype[0] ? f->ctype : "application/json",
                          NULL, ctx->body.p, ctx->body.len, NULL, 0);
        } else {
            const jval_t *cached = ccache_get(ctx->target);
            if (!strcmp(ctx->cmd, "load") && cached) {
                send_json(fr, 200, "OK", cached, NULL);
            } else if (!strcmp(ctx->cmd, "status") && cached) {
                jval_t *st = j_obj();
                j_set(st, "version", j_str("Astra"));
                j_set(st, "uptime", j_int(3600));
                j_set(st, "observer", j_bool(0));
                j_set(st, "dvb_list", j_arr());
                j_set(st, "net_list", j_arr());
                send_json(fr, 200, "OK", st, NULL);
                j_free(st);
            } else {
                char msg[256];
                snprintf(msg, sizeof msg, "Cluster host %s unreachable: %s",
                         ctx->target, err ? err : "failed");
                send_detail(fr, 502, "Bad Gateway", msg, NULL);
            }
        }
    }
    buf_free(&ctx->body);
    free(ctx);
}
static const fetch_cb_t g_cfetch_cb = {cfetch_head, cfetch_data, cfetch_done};

static void handle_cluster_control(front_t *fr, const req_t *r)
{
    (void)require_auth(fr, r);
    char target[256] = "";
    if (r->x_cluster_target[0])
        snprintf(target, sizeof target, "%s", r->x_cluster_target);
    else
        query_get(r->query, "target", target, sizeof target);
    char *col = strrchr(target, ':');
    if (!col || col == target) {
        send_detail(fr, 400, "Bad Request", "Missing X-Cluster-Target host:port", NULL);
        return;
    }
    jval_t *body = j_parse_n((const char *)r->body, r->body_len);
    if (!j_is_obj(body)) {
        j_free(body);
        send_detail(fr, 400, "Bad Request", "Invalid JSON", NULL);
        return;
    }
    const char *cmd = j_get_str(body, "cmd", "");
    if (!strcmp(cmd, "scan-init")) {
        const char *st = j_get_str(body, "scan", "");
        if (!strncmp(st, "stream://", 9)) {
            char sid_hex[16];
            gen_uuid_hex(sid_hex, sizeof sid_hex, 5);
            for (int i = 0; i < MAX_SCANS; i++) {
                if (!g_scans[i].active) {
                    g_scans[i].active = 1;
                    snprintf(g_scans[i].id, sizeof g_scans[i].id, "%s", sid_hex);
                    snprintf(g_scans[i].stream_id, sizeof g_scans[i].stream_id, "%s", st + 9);
                    snprintf(g_scans[i].cluster_host, sizeof g_scans[i].cluster_host, "%s", target);
                    break;
                }
            }
            j_free(body);
            jval_t *v = j_obj();
            j_set(v, "scan-init", j_str("ok"));
            j_set(v, "id", j_str(sid_hex));
            send_json(fr, 200, "OK", v, NULL);
            j_free(v);
            return;
        }
    } else if (!strcmp(cmd, "scan-kill")) {
        const char *id = j_get_str(body, "id", "");
        for (int i = 0; i < MAX_SCANS; i++)
            if (g_scans[i].active && !strcmp(g_scans[i].id, id))
                g_scans[i].active = 0;
        j_free(body);
        jval_t *v = j_obj();
        j_set(v, "scan-kill", j_str("ok"));
        j_set(v, "success", j_bool(1));
        send_json(fr, 200, "OK", v, NULL);
        j_free(v);
        return;
    }

    char ruser[96] = "", rpass[96] = "";
    const jval_t *servers = j_get(g_cfg, "servers");
    if (j_is_arr(servers)) {
        for (jval_t *srv = servers->child; srv; srv = srv->next) {
            char shp[128];
            int sp = (int)j_get_int(srv, "port", 8000);
            if (j_is_str(j_get(srv, "port"))) sp = atoi(j_get_str(srv, "port", "8000"));
            snprintf(shp, sizeof shp, "%s:%d", j_get_str(srv, "host", ""), sp);
            if (!strcmp(shp, target)) {
                snprintf(ruser, sizeof ruser, "%s", j_get_str(srv, "user", ""));
                snprintf(rpass, sizeof rpass, "%s", j_get_str(srv, "pass", ""));
                break;
            }
        }
    }
    char extra[768] = "Content-Type: application/json\r\n";
    if (r->x_cluster_auth[0]) {
        snprintf(extra + strlen(extra), sizeof extra - strlen(extra), "Authorization: %s\r\n", r->x_cluster_auth);
    } else if (ruser[0]) {
        char cred[256], b64c[384];
        if (rpass[0]) snprintf(cred, sizeof cred, "%s:%s", ruser, rpass);
        else snprintf(cred, sizeof cred, "%s", ruser);
        b64_encode((const uint8_t *)cred, strlen(cred), b64c, sizeof b64c);
        snprintf(extra + strlen(extra), sizeof extra - strlen(extra), "Authorization: Basic %s\r\n", b64c);
    }

    char url[512];
    snprintf(url, sizeof url, "http://%s/control/", target);
    cfetch_ctx_t *ctx = calloc(1, sizeof *ctx);
    ctx->fr = fr;
    snprintf(ctx->target, sizeof ctx->target, "%s", target);
    snprintf(ctx->cmd, sizeof ctx->cmd, "%s", cmd);
    j_free(body);

    fr->mode = FR_CFETCH;
    fr->cfetch = fetch_start_ex("POST", url, "AstraG/2.0", extra, r->body, r->body_len,
                                &g_cfetch_cb, ctx, 8.0, 8.0);
    if (!fr->cfetch) {
        free(ctx);
        send_detail(fr, 502, "Bad Gateway", "Cluster request failed", NULL);
    }
}

/* ----------------------------------------------------------- HTTP router */

static void ctl_http_dispatch(front_t *fr, const req_t *r)
{
    if (!strcasecmp(r->method, "OPTIONS")) {
        front_respond_status_raw(fr, 204, "No Content",
                                 "Access-Control-Allow-Origin: *\r\n"
                                 "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n"
                                 "Access-Control-Allow-Headers: *\r\n", NULL, 0);
        return;
    }

    /* WebSocket Upgrades */
    if (!strcasecmp(r->upgrade, "websocket") && r->sec_ws_key[0]) {
        char concat[256];
        snprintf(concat, sizeof concat, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", r->sec_ws_key);
        uint8_t sha[SHA_DIGEST_LENGTH];
        SHA1((const uint8_t *)concat, strlen(concat), sha);
        char accept[64];
        b64_encode(sha, SHA_DIGEST_LENGTH, accept, sizeof accept);
        if (!strcmp(r->path, "/control/event/") || !strcmp(r->path, "/control/event")) {
            ws_upgrade(fr, accept, 0, NULL);
            return;
        }
        if (!strcmp(r->path, "/api/cluster-ws")) {
            char hp[128] = "";
            query_get(r->query, "host", hp, sizeof hp);
            ws_upgrade(fr, accept, 1, hp);
            return;
        }
        front_error(fr, 404, "WebSocket endpoint not found");
        return;
    }

    const char *p = r->path;
    int is_post = !strcasecmp(r->method, "POST");
    int is_get = !strcasecmp(r->method, "GET") || !strcasecmp(r->method, "HEAD");

    if (is_get && !strcmp(p, "/__health")) {
        char body[128];
        int n = snprintf(body, sizeof body, "{\"status\":\"ok\",\"version\":\"%s\"}", ASTRAG_VERSION);
        front_respond(fr, 200, "OK", "application/json", NULL, body, (size_t)n, NULL, 0);
        return;
    }

    if (is_post && (!strcmp(p, "/control/") || !strcmp(p, "/control"))) {
        handle_control_api(fr, r);
        return;
    }
    if (is_post && (!strcmp(p, "/control/account/") || !strcmp(p, "/control/account"))) {
        handle_account_change(fr, r);
        return;
    }
    if (is_post && (!strcmp(p, "/control/reset-password/") || !strcmp(p, "/control/reset-password"))) {
        handle_reset_password(fr, r);
        return;
    }
    if (is_post && !strcmp(p, "/api/cluster-control")) {
        handle_cluster_control(fr, r);
        return;
    }

    if (!is_get) {
        front_error(fr, 405, "Method Not Allowed");
        return;
    }

    /* Static UI assets */
    if (!strcmp(p, "/") || !strcmp(p, "/index.html")) {
        serve_ui_gz(fr, r, www_index_html_gz, www_index_html_gz_len, &g_ui_index_plain,
                    "text/html; charset=utf-8", "Cache-Control: no-cache\r\n");
        return;
    }
    if (!strcmp(p, "/mod.js")) {
        serve_ui_gz(fr, r, www_mod_js_gz, www_mod_js_gz_len, &g_ui_mod_plain,
                    "application/javascript; charset=utf-8", "Cache-Control: no-store\r\n");
        return;
    }
    if (!strcmp(p, "/account/") || !strcmp(p, "/account") || !strcmp(p, "/account/index.html")) {
        serve_ui_gz(fr, r, www_account_html_gz, www_account_html_gz_len, &g_ui_account_plain,
                    "text/html; charset=utf-8",
                    "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n"
                    "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; form-action 'none'; base-uri 'none'\r\n");
        return;
    }
    if (!strcmp(p, "/favicon.png") || !strcmp(p, "/favicon.ico")) {
        front_respond(fr, 200, "OK", "image/png", "Cache-Control: public, max-age=86400\r\n",
                      www_favicon_png, www_favicon_png_len, NULL, !strcasecmp(r->method, "HEAD"));
        return;
    }

    /* Default playlists */
    if (!strcmp(p, "/playlist.m3u8") || !strcmp(p, "/playlist.m3u")) {
        serve_m3u_playlist(fr, r);
        return;
    }
    if (!strcmp(p, "/playlist.xspf")) {
        serve_xspf_playlist(fr, r);
        return;
    }

    /* /play/cluster/{srv}/{id}... */
    if (!strncmp(p, "/play/cluster/", 14)) {
        const char *rest = p + 14;
        const char *sl = strchr(rest, '/');
        if (sl && sl > rest) {
            char skey[128], tail[512];
            snprintf(skey, sizeof skey, "%.*s", (int)(sl - rest), rest);
            snprintf(tail, sizeof tail, "%s", sl + 1);
            char *seg_pos = strstr(tail, "/segment/");
            size_t tl = strlen(tail);
            if (seg_pos) {
                *seg_pos = 0;
                handle_media_play_seg(fr, r, tail, seg_pos + 9, skey);
                return;
            }
            if (tl > 11 && !strcmp(tail + tl - 11, "/index.m3u8")) {
                tail[tl - 11] = 0;
                handle_media_play_hls(fr, r, tail, skey);
                return;
            }
            if (tl > 5 && !strcmp(tail + tl - 5, ".m3u8")) {
                tail[tl - 5] = 0;
                handle_media_play_hls(fr, r, tail, skey);
                return;
            }
            if (tl > 3 && !strcmp(tail + tl - 3, ".ts"))
                tail[tl - 3] = 0;
            handle_media_play_ts(fr, r, tail, skey);
            return;
        }
    }

    /* /play/{id}... */
    if (!strncmp(p, "/play/", 6)) {
        char tail[2048];
        snprintf(tail, sizeof tail, "%.*s", (int)(sizeof tail - 1), p + 6);
        char *seg_pos = strstr(tail, "/segment/");
        size_t tl = strlen(tail);
        if (seg_pos && seg_pos[9]) {
            *seg_pos = 0;
            handle_media_play_seg(fr, r, tail, seg_pos + 9, NULL);
            return;
        }
        if (tl > 11 && !strcmp(tail + tl - 11, "/index.m3u8")) {
            tail[tl - 11] = 0;
            handle_media_play_hls(fr, r, tail, NULL);
            return;
        }
        if (tl > 5 && !strcmp(tail + tl - 5, ".m3u8")) {
            tail[tl - 5] = 0;
            handle_media_play_hls(fr, r, tail, NULL);
            return;
        }
        if (tl > 3 && !strcmp(tail + tl - 3, ".ts"))
            tail[tl - 3] = 0;
        handle_media_play_ts(fr, r, tail, NULL);
        return;
    }

    /* /live/{id}... */
    if (!strncmp(p, "/live/", 6)) {
        char tail[2048];
        snprintf(tail, sizeof tail, "%.*s", (int)(sizeof tail - 1), p + 6);
        size_t tl = strlen(tail);
        int req_port = fr->listen_port;
        char osid[128], oseg[256];
        int omode = 0;
        if (tl > 5 && !strcmp(tail + tl - 5, ".m3u8")) {
            if (resolve_http_output(p, req_port, osid, sizeof osid, &omode, oseg, sizeof oseg)) {
                handle_media_play_hls(fr, r, osid, NULL);
                return;
            }
            tail[tl - 5] = 0;
            handle_media_play_hls(fr, r, tail, NULL);
            return;
        }
        if (tl > 3 && !strcmp(tail + tl - 3, ".ts")) {
            if (resolve_http_output(p, req_port, osid, sizeof osid, &omode, oseg, sizeof oseg)) {
                handle_media_play_ts(fr, r, osid, NULL);
                return;
            }
            tail[tl - 3] = 0;
            handle_media_play_ts(fr, r, tail, NULL);
            return;
        }
        if (resolve_http_output(p, req_port, osid, sizeof osid, &omode, oseg, sizeof oseg)) {
            if (omode == 1) handle_media_play_hls(fr, r, osid, NULL);
            else if (omode == 2) handle_media_play_seg(fr, r, osid, oseg, NULL);
            else handle_media_play_ts(fr, r, osid, NULL);
            return;
        }
        handle_media_play_ts(fr, r, tail, NULL);
        return;
    }

    /* Custom playlist name /{custom}.m3u8|.m3u|.xspf */
    size_t pl = strlen(p);
    if (p[0] == '/' && !strchr(p + 1, '/')) {
        const char *conf_pl = j_get_str(j_get(g_cfg, "settings"), "http_play_playlist_name", "playlist");
        if (!*conf_pl) conf_pl = "playlist";
        if (pl > 5 && !strcmp(p + pl - 5, ".m3u8")) {
            char name[256];
            snprintf(name, sizeof name, "%.*s", (int)(pl - 6), p + 1);
            if (!strcmp(name, conf_pl)) { serve_m3u_playlist(fr, r); return; }
        } else if (pl > 4 && !strcmp(p + pl - 4, ".m3u")) {
            char name[256];
            snprintf(name, sizeof name, "%.*s", (int)(pl - 5), p + 1);
            if (!strcmp(name, conf_pl)) { serve_m3u_playlist(fr, r); return; }
        } else if (pl > 5 && !strcmp(p + pl - 5, ".xspf")) {
            char name[256];
            snprintf(name, sizeof name, "%.*s", (int)(pl - 6), p + 1);
            if (!strcmp(name, conf_pl)) { serve_xspf_playlist(fr, r); return; }
        }
    }

    /* Custom HTTP output routes */
    char osid[128], oseg[256];
    int omode = 0;
    if (resolve_http_output(p, fr->listen_port, osid, sizeof osid, &omode, oseg, sizeof oseg)) {
        if (omode == 1) handle_media_play_hls(fr, r, osid, NULL);
        else if (omode == 2) handle_media_play_seg(fr, r, osid, oseg, NULL);
        else handle_media_play_ts(fr, r, osid, NULL);
        return;
    }

    /* Direct /{id}.m3u8, /{id}/index.m3u8, /{id}.ts */
    if (pl > 5 && !strcmp(p + pl - 5, ".m3u8") && !strchr(p + 1, '/')) {
        char name[128];
        snprintf(name, sizeof name, "%.*s", (int)(pl - 6), p + 1);
        if (find_stream_cfg(name)) {
            handle_media_play_hls(fr, r, name, NULL);
            return;
        }
    }
    if (pl > 11 && !strcmp(p + pl - 11, "/index.m3u8")) {
        char name[128];
        snprintf(name, sizeof name, "%.*s", (int)(pl - 12), p + 1);
        if (!strchr(name, '/') && find_stream_cfg(name)) {
            handle_media_play_hls(fr, r, name, NULL);
            return;
        }
    }
    if (pl > 3 && !strcmp(p + pl - 3, ".ts") && !strchr(p + 1, '/')) {
        char name[128];
        snprintf(name, sizeof name, "%.*s", (int)(pl - 4), p + 1);
        if (find_stream_cfg(name)) {
            handle_media_play_ts(fr, r, name, NULL);
            return;
        }
    }

    front_error(fr, 404, "Not Found");
}

void ctl_http_handle(front_t *fr, size_t head_len, size_t body_len)
{
    req_t r;
    parse_req(fr, head_len, body_len, &r);
    ctl_http_dispatch(fr, &r);
    if (!fr->ev.dead)
        buf_drop(&fr->in, head_len + body_len);
}

/* ----------------------------------------------------------- init / cleanup */

int ctl_init(const char *config_path, const char *cli_host, int cli_port)
{
    g_started_wall = time(NULL);
    if (config_path && *config_path)
        snprintf(g_conf_path, sizeof g_conf_path, "%s", config_path);
    else if (getenv("ASTRA_CONFIG_FILE"))
        snprintf(g_conf_path, sizeof g_conf_path, "%s", getenv("ASTRA_CONFIG_FILE"));
    else if (access("/etc/astrag/astrag.conf", F_OK) == 0)
        snprintf(g_conf_path, sizeof g_conf_path, "/etc/astrag/astrag.conf");
    else
        snprintf(g_conf_path, sizeof g_conf_path, "./astrag.conf");

    if (cli_host && *cli_host)
        snprintf(g_host, sizeof g_host, "%s", cli_host);
    else if (getenv("ASTRA_HOST"))
        snprintf(g_host, sizeof g_host, "%s", getenv("ASTRA_HOST"));

    if (cli_port > 0)
        g_port = cli_port;
    else if (getenv("ASTRA_PORT"))
        g_port = atoi(getenv("ASTRA_PORT")) ?: 8000;
    else
        g_port = 8000;

    char err[256] = "";
    jval_t *loaded = load_disk_config(err, sizeof err);
    if (!loaded) {
        CLOG("failed to load %s: %s", g_conf_path, err);
        return -1;
    }
    if (cli_port > 0) {
        g_port = cli_port;
        j_set(loaded, "port", j_int(g_port));
        j_set(loaded, "control_port", j_int(g_port));
    }
    if (cli_host && *cli_host) {
        snprintf(g_host, sizeof g_host, "%s", cli_host);
        j_set(loaded, "host", j_str(g_host));
    }

    if (listener_add(g_host, g_port) < 0) {
        j_free(loaded);
        return -1;
    }
    apply_config(loaded, 0, 1, err, sizeof err);
    j_free(loaded);
    add_log("info", "%s started on %s:%d", ASTRAG_VERSION, g_host, g_port);
    CLOG("%s listening on %s:%d (config: %s)", ASTRAG_VERSION, g_host, g_port, g_conf_path);
    return 0;
}

void ctl_cleanup(void)
{
    for (int i = 0; i < g_ncstreams; i++)
        j_free(g_cstreams[i].cfg);
    g_ncstreams = 0;
    free(g_calias);
    g_calias = NULL;
    g_ncalias = 0;
    for (int i = 0; i < g_nccache; i++)
        j_free(g_ccache[i].cfg);
    g_nccache = 0;
    if (g_csync) {
        for (int i = 0; i < MAX_CLUSTER_SRV; i++) j_free(g_csync->results[i]);
        j_free(g_csync->servers);
        free(g_csync);
        g_csync = NULL;
    }
    j_free(g_cfg);
    g_cfg = NULL;
    buf_free(&g_ui_index_plain);
    buf_free(&g_ui_mod_plain);
    buf_free(&g_ui_account_plain);
}

int ctl_verify_password(const char *pw, const char *stored)
{
    return verify_password(pw, stored);
}

int ctl_atomic_write_file(const char *path, const char *data, size_t len, unsigned int mode)
{
    return atomic_write_file(path, data, len, (mode_t)mode);
}

int ctl_read_file_str(const char *path, char **out, size_t *out_len)
{
    return read_file_str(path, out, out_len);
}
