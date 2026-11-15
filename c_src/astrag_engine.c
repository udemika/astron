#define _GNU_SOURCE
#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0

#include "astrag.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

double g_now = 0.0;
int g_ep = -1;
channel_t *g_channels = NULL;
front_t *g_fronts = NULL;
volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_hup = 0;

static int g_hls_parallel = 2;
static SSL_CTX *g_ssl = NULL;
static unsigned long long g_sess_seq = 0;
static buf_t g_scr = {0};

#define ELOG(...) do { fprintf(stderr, "[astrag] " __VA_ARGS__); fputc('\n', stderr); } while (0)

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }
static double clampd(double v, double lo, double hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* ------------------------------------------------------------------ buffers */

int buf_reserve(buf_t *b, size_t n)
{
    if (b->len + n <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap : 1024;
    while (nc < b->len + n)
        nc *= 2;
    void *q = realloc(b->p, nc);
    if (!q)
        return -1;
    b->p = q;
    b->cap = nc;
    return 0;
}

int buf_add(buf_t *b, const void *d, size_t n)
{
    if (!n)
        return 0;
    if (buf_reserve(b, n))
        return -1;
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

int buf_str(buf_t *b, const char *s)
{
    return s ? buf_add(b, s, strlen(s)) : 0;
}

int buf_fmt(buf_t *b, const char *fmt, ...)
{
    va_list ap;
    char tmp[1024];
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if ((size_t)n < sizeof tmp)
        return buf_add(b, tmp, (size_t)n);
    if (buf_reserve(b, (size_t)n + 1))
        return -1;
    va_start(ap, fmt);
    vsnprintf((char *)b->p + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
    return 0;
}

void buf_drop(buf_t *b, size_t n)
{
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
}

void buf_free(buf_t *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

/* --------------------------------------------------------------- event core */

void ev_watch(ev_t *e, uint32_t mask)
{
    if (e->fd < 0 || e->dead)
        return;
    if (e->reg && e->mask == mask)
        return;
    struct epoll_event ee;
    memset(&ee, 0, sizeof ee);
    ee.events = mask;
    ee.data.ptr = e;
    if (epoll_ctl(g_ep, e->reg ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, e->fd, &ee) == 0) {
        e->reg = 1;
        e->mask = mask;
    }
}

void ev_close(ev_t *e)
{
    if (e->fd >= 0) {
        if (e->reg)
            epoll_ctl(g_ep, EPOLL_CTL_DEL, e->fd, NULL);
        close(e->fd);
    }
    e->fd = -1;
    e->reg = 0;
}

typedef struct grave {
    void (*fn)(void *);
    void *p;
    struct grave *next;
} grave_t;
static grave_t *g_grave = NULL;

void bury(void (*fn)(void *), void *p)
{
    grave_t *g = malloc(sizeof *g);
    if (!g) {
        fn(p);
        return;
    }
    g->fn = fn;
    g->p = p;
    g->next = g_grave;
    g_grave = g;
}

static void reap(void)
{
    while (g_grave) {
        grave_t *g = g_grave;
        g_grave = g->next;
        g->fn(g->p);
        free(g);
    }
}

static void set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* --------------------------------------------------------------------- DNS */

typedef void (*dns_cb)(void *arg, int ok, struct in_addr a);
struct dnsq {
    char host[256];
    struct in_addr addr;
    int ok, cancelled;
    dns_cb cb;
    void *arg;
    struct dnsq *next;
};

static pthread_mutex_t g_dmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_dcv = PTHREAD_COND_INITIALIZER;
static dnsq_t *g_dqh = NULL, *g_dqt = NULL;
static int g_dpipe[2] = {-1, -1};
static ev_t g_dev;
static struct {
    char host[256];
    struct in_addr a;
    double exp;
} g_dcache[256];
static int g_dci = 0;

static void *dns_thread(void *u)
{
    (void)u;
    for (;;) {
        pthread_mutex_lock(&g_dmu);
        while (!g_dqh)
            pthread_cond_wait(&g_dcv, &g_dmu);
        dnsq_t *q = g_dqh;
        g_dqh = q->next;
        if (!g_dqh)
            g_dqt = NULL;
        pthread_mutex_unlock(&g_dmu);
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        q->ok = getaddrinfo(q->host, NULL, &hints, &res) == 0 && res;
        if (q->ok)
            q->addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        if (res)
            freeaddrinfo(res);
        ssize_t w;
        do {
            w = write(g_dpipe[1], &q, sizeof q);
        } while (w < 0 && errno == EINTR);
    }
    return NULL;
}

static int dns_lookup(const char *host, dns_cb cb, void *arg, struct in_addr *out, dnsq_t **pend)
{
    *pend = NULL;
    if (!strcasecmp(host, "localhost")) {
        out->s_addr = htonl(INADDR_LOOPBACK);
        return 1;
    }
    if (inet_pton(AF_INET, host, out) == 1)
        return 1;
    for (int i = 0; i < 256; i++) {
        if (g_dcache[i].exp > g_now && !strcmp(g_dcache[i].host, host)) {
            *out = g_dcache[i].a;
            return 1;
        }
    }
    dnsq_t *q = calloc(1, sizeof *q);
    if (!q)
        return -1;
    snprintf(q->host, sizeof q->host, "%s", host);
    q->cb = cb;
    q->arg = arg;
    pthread_mutex_lock(&g_dmu);
    if (g_dqt)
        g_dqt->next = q;
    else
        g_dqh = q;
    g_dqt = q;
    pthread_cond_signal(&g_dcv);
    pthread_mutex_unlock(&g_dmu);
    *pend = q;
    return 0;
}

static void dns_on_ready(void)
{
    dnsq_t *qs[64];
    ssize_t n = read(g_dpipe[0], qs, sizeof qs);
    if (n <= 0)
        return;
    for (ssize_t i = 0; i < n / (ssize_t)sizeof(dnsq_t *); i++) {
        dnsq_t *q = qs[i];
        if (q->ok) {
            snprintf(g_dcache[g_dci].host, sizeof g_dcache[0].host, "%s", q->host);
            g_dcache[g_dci].a = q->addr;
            g_dcache[g_dci].exp = g_now + 120.0;
            g_dci = (g_dci + 1) % 256;
        }
        if (!q->cancelled)
            q->cb(q->arg, q->ok, q->addr);
        free(q);
    }
}

/* --------------------------------------------------------------------- URLs */

static int b64(const char *in, size_t n, char *out, size_t outsz)
{
    if (outsz < 4 * ((n + 2) / 3) + 1)
        return -1;
    EVP_EncodeBlock((unsigned char *)out, (const unsigned char *)in, (int)n);
    return 0;
}

static int url_parse(const char *url, int *https, char *host, size_t hl, int *port, char *target, size_t tl,
                     char *auth, size_t al)
{
    const char *p = url;
    if (!strncasecmp(p, "http://", 7)) {
        *https = 0;
        p += 7;
    } else if (!strncasecmp(p, "https://", 8)) {
        *https = 1;
        p += 8;
    } else
        return -1;
    const char *end = p + strcspn(p, "/?#");
    auth[0] = 0;
    const char *at = memrchr(p, '@', (size_t)(end - p));
    if (at) {
        if (b64(p, (size_t)(at - p), auth, al))
            return -1;
        p = at + 1;
    }
    const char *colon = memchr(p, ':', (size_t)(end - p));
    const char *he = colon ? colon : end;
    if (he == p || (size_t)(he - p) >= hl)
        return -1;
    memcpy(host, p, (size_t)(he - p));
    host[he - p] = 0;
    *port = *https ? 443 : 80;
    if (colon) {
        int v = atoi(colon + 1);
        if (v <= 0 || v > 65535)
            return -1;
        *port = v;
    }
    size_t tlen = strcspn(end, "#");
    if (tlen == 0) {
        snprintf(target, tl, "/");
    } else if (*end == '?') {
        if (tlen + 2 > tl)
            return -1;
        target[0] = '/';
        memcpy(target + 1, end, tlen);
        target[tlen + 1] = 0;
    } else {
        if (tlen + 1 > tl)
            return -1;
        memcpy(target, end, tlen);
        target[tlen] = 0;
    }
    return 0;
}

static void url_normalize(char *u)
{
    char *s = strstr(u, "://");
    if (!s)
        return;
    char *path = strchr(s + 3, '/');
    if (!path)
        return;
    char *q = path + strcspn(path, "?#");
    char tail[4096];
    snprintf(tail, sizeof tail, "%s", q);
    *q = 0;
    char out[4096];
    size_t o = 0;
    char *seg = path + 1;
    out[o++] = '/';
    for (;;) {
        char *sl = strchr(seg, '/');
        size_t n = sl ? (size_t)(sl - seg) : strlen(seg);
        if (n == 1 && seg[0] == '.') {
        } else if (n == 2 && seg[0] == '.' && seg[1] == '.') {
            if (o > 1) {
                o--;
                while (o > 0 && out[o - 1] != '/')
                    o--;
            }
        } else if (o + n + 1 < sizeof out) {
            memcpy(out + o, seg, n);
            o += n;
            if (sl)
                out[o++] = '/';
        }
        if (!sl)
            break;
        seg = sl + 1;
    }
    out[o] = 0;
    size_t room = 4096 - (size_t)(path - u);
    snprintf(path, room, "%s%s", out, tail);
}

static void url_resolve(const char *base, const char *ref, char *out, size_t outsz)
{
    if (strstr(ref, "://") && strcspn(ref, ":") < strcspn(ref, "/?")) {
        snprintf(out, outsz, "%s", ref);
        return;
    }
    const char *s = strstr(base, "://");
    if (!s) {
        snprintf(out, outsz, "%s", ref);
        return;
    }
    if (ref[0] == '/' && ref[1] == '/') {
        snprintf(out, outsz, "%.*s:%s", (int)(s - base), base, ref);
        return;
    }
    const char *auth_end = s + 3 + strcspn(s + 3, "/?#");
    if (ref[0] == '/') {
        snprintf(out, outsz, "%.*s%s", (int)(auth_end - base), base, ref);
    } else if (ref[0] == '?') {
        size_t pl = strcspn(base, "?#");
        snprintf(out, outsz, "%.*s%s", (int)pl, base, ref);
    } else {
        size_t pl = strcspn(base, "?#");
        const char *last = NULL;
        for (const char *c = auth_end; c < base + pl; c++)
            if (*c == '/')
                last = c;
        if (!last)
            snprintf(out, outsz, "%.*s/%s", (int)(auth_end - base), base, ref);
        else
            snprintf(out, outsz, "%.*s%s", (int)(last - base + 1), base, ref);
    }
    if (outsz >= 4096)
        url_normalize(out);
}

/* -------------------------------------------------------------- HTTP client */

static fetch_t *g_fetches = NULL;

static void fetch_free(void *p)
{
    fetch_t *f = p;
    buf_free(&f->req);
    buf_free(&f->head);
    free(f->extra_hdrs);
    free(f->post_body);
    free(f);
}

static void fetch_kill(fetch_t *f)
{
    if (f->ev.dead)
        return;
    f->ev.dead = 1;
    if (f->dns) {
        f->dns->cancelled = 1;
        f->dns = NULL;
    }
    if (f->ssl) {
        SSL_free(f->ssl);
        f->ssl = NULL;
    }
    ev_close(&f->ev);
    if (f->gprev)
        f->gprev->gnext = f->gnext;
    else if (g_fetches == f)
        g_fetches = f->gnext;
    if (f->gnext)
        f->gnext->gprev = f->gprev;
    bury(fetch_free, f);
}

void fetch_cancel(fetch_t *f)
{
    if (f)
        fetch_kill(f);
}

static void fetch_end(fetch_t *f, int ok, const char *err)
{
    if (f->ev.dead)
        return;
    const fetch_cb_t *cb = f->cb;
    fetch_kill(f);
    cb->done(f, ok, err);
}

static void fetch_begin(fetch_t *f);

static void fetch_defer(fetch_t *f, const char *msg)
{
    f->derr = msg;
    f->deadline = 0;
}

static void fetch_connect(fetch_t *f, struct in_addr a)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fetch_defer(f, "socket failed");
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)f->port);
    sa.sin_addr = a;
    f->ev.fd = fd;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0 && errno != EINPROGRESS) {
        fetch_defer(f, "connect failed");
        return;
    }
    f->st = F_CONN;
    f->deadline = g_now + f->conn_to;
    ev_watch(&f->ev, EPOLLOUT);
}

static void fetch_dns_done(void *arg, int ok, struct in_addr a)
{
    fetch_t *f = arg;
    f->dns = NULL;
    if (f->ev.dead)
        return;
    if (!ok) {
        fetch_defer(f, "DNS lookup failed");
        return;
    }
    fetch_connect(f, a);
}

static void fetch_begin(fetch_t *f)
{
    if (url_parse(f->url, &f->https, f->host, sizeof f->host, &f->port, f->target, sizeof f->target, f->auth,
                  sizeof f->auth)) {
        fetch_defer(f, "invalid URL");
        return;
    }
    f->req.len = 0;
    f->req_off = 0;
    int defport = (f->https && f->port == 443) || (!f->https && f->port == 80);
    const char *meth = f->method[0] ? f->method : "GET";
    buf_fmt(&f->req, "%s %s HTTP/1.1\r\nHost: %s", meth, f->target, f->host);
    if (!defport)
        buf_fmt(&f->req, ":%d", f->port);
    buf_fmt(&f->req,
            "\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\n"
            "Connection: close\r\n",
            f->ua);
    if (f->auth[0])
        buf_fmt(&f->req, "Authorization: Basic %s\r\n", f->auth);
    if (f->extra_hdrs && f->extra_hdrs[0])
        buf_str(&f->req, f->extra_hdrs);
    if (f->post_body || f->post_len > 0 || !strcasecmp(meth, "POST"))
        buf_fmt(&f->req, "Content-Length: %zu\r\n", f->post_len);
    buf_str(&f->req, "\r\n");
    if (f->post_body && f->post_len > 0)
        buf_add(&f->req, f->post_body, f->post_len);

    f->st = F_DNS;
    f->deadline = g_now + f->conn_to;
    struct in_addr a;
    dnsq_t *pend;
    int r = dns_lookup(f->host, fetch_dns_done, f, &a, &pend);
    if (r == 1)
        fetch_connect(f, a);
    else if (r == 0)
        f->dns = pend;
    else
        fetch_defer(f, "DNS queue failed");
}

fetch_t *fetch_start_ex(const char *method, const char *url, const char *ua,
                        const char *extra_hdrs, const void *body, size_t body_len,
                        const fetch_cb_t *cb, void *owner, double conn_to, double idle_to)
{
    fetch_t *f = calloc(1, sizeof *f);
    if (!f)
        return NULL;
    f->ev.type = EV_FETCH;
    f->ev.fd = -1;
    f->ev.obj = f;
    snprintf(f->method, sizeof f->method, "%s", method && *method ? method : "GET");
    snprintf(f->url, sizeof f->url, "%s", url);
    snprintf(f->ua, sizeof f->ua, "%s", ua && *ua ? ua : "AstraG/2.0");
    if (extra_hdrs && *extra_hdrs)
        f->extra_hdrs = strdup(extra_hdrs);
    if (body && body_len > 0) {
        f->post_body = malloc(body_len);
        if (f->post_body) {
            memcpy(f->post_body, body, body_len);
            f->post_len = body_len;
        }
    }
    f->cb = cb;
    f->owner = owner;
    f->conn_to = conn_to;
    f->idle_to = idle_to;
    f->clen = -1;
    f->gnext = g_fetches;
    if (g_fetches)
        g_fetches->gprev = f;
    g_fetches = f;
    fetch_begin(f);
    return f;
}

fetch_t *fetch_start(const char *url, const char *ua, const fetch_cb_t *cb, void *owner, double conn_to,
                     double idle_to)
{
    return fetch_start_ex("GET", url, ua, NULL, NULL, 0, cb, owner, conn_to, idle_to);
}

void fetch_pause(fetch_t *f, int on)
{
    if (!f || f->ev.dead || f->paused == on)
        return;
    f->paused = on;
    if (f->st >= F_HEAD)
        ev_watch(&f->ev, on ? 0 : EPOLLIN);
}

static void fetch_restart_redirect(fetch_t *f, const char *loc)
{
    char nu[4096];
    url_resolve(f->url, loc, nu, sizeof nu);
    snprintf(f->url, sizeof f->url, "%s", nu);
    if (f->ssl) {
        SSL_free(f->ssl);
        f->ssl = NULL;
    }
    ev_close(&f->ev);
    f->head.len = 0;
    f->status = 0;
    f->chunked = 0;
    f->clen = -1;
    f->ctype[0] = 0;
    f->redirects++;
    fetch_begin(f);
}

static void fetch_body(fetch_t *f, const uint8_t *d, size_t n)
{
    if (f->chunked) {
        while (n > 0 && !f->ev.dead) {
            if (f->cst == 0 || f->cst == 3) {
                uint8_t c = *d++;
                n--;
                if (c == '\n') {
                    f->cl[f->cll] = 0;
                    if (f->cst == 3) {
                        if (f->cll == 0) {
                            fetch_end(f, 1, NULL);
                            return;
                        }
                        f->cll = 0;
                        continue;
                    }
                    f->remain = strtoll(f->cl, NULL, 16);
                    f->cll = 0;
                    f->cst = f->remain > 0 ? 1 : 3;
                } else if (c != '\r' && f->cll < (int)sizeof f->cl - 1) {
                    if (f->cst == 0 && c == ';')
                        f->cl[f->cll++] = 0;
                    else
                        f->cl[f->cll++] = (char)c;
                }
            } else if (f->cst == 1) {
                size_t t = min_sz(n, (size_t)f->remain);
                f->cb->data(f, d, t);
                d += t;
                n -= t;
                f->remain -= (int64_t)t;
                if (f->remain == 0)
                    f->cst = 2;
            } else {
                uint8_t c = *d++;
                n--;
                if (c == '\n')
                    f->cst = 0;
            }
        }
        return;
    }
    if (f->clen >= 0) {
        size_t t = min_sz(n, (size_t)f->remain);
        if (t)
            f->cb->data(f, d, t);
        if (f->ev.dead)
            return;
        f->remain -= (int64_t)t;
        if (f->remain <= 0)
            fetch_end(f, 1, NULL);
        return;
    }
    f->cb->data(f, d, n);
}

static void fetch_parse_head(fetch_t *f, size_t hl)
{
    char *h = (char *)f->head.p;
    h[hl - 2] = 0;
    f->status = 0;
    sscanf(h, "HTTP/%*d.%*d %d", &f->status);
    if (!f->status)
        sscanf(h, "HTTP/%*d %d", &f->status);
    char loc[4096] = "";
    char *line = strchr(h, '\n');
    while (line && *++line) {
        char *e = strchr(line, '\n');
        if (e)
            *e = 0;
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\r')
            line[--ll] = 0;
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = 0;
            char *v = colon + 1;
            while (*v == ' ' || *v == '\t')
                v++;
            if (!strcasecmp(line, "content-length"))
                f->clen = strtoll(v, NULL, 10);
            else if (!strcasecmp(line, "transfer-encoding") && strcasestr(v, "chunked"))
                f->chunked = 1;
            else if (!strcasecmp(line, "location"))
                snprintf(loc, sizeof loc, "%s", v);
            else if (!strcasecmp(line, "content-type"))
                snprintf(f->ctype, sizeof f->ctype, "%s", v);
        }
        line = e;
    }
    if (f->chunked)
        f->clen = -1;
    f->remain = f->clen;
    if ((f->status == 301 || f->status == 302 || f->status == 303 || f->status == 307 || f->status == 308) &&
        loc[0] && f->redirects < 8) {
        fetch_restart_redirect(f, loc);
        return;
    }
    f->st = F_BODY;
    f->cb->head(f);
    if (f->ev.dead)
        return;
    if (f->status == 204 || f->status == 304 || f->clen == 0) {
        fetch_end(f, 1, NULL);
        return;
    }
    size_t left = f->head.len - hl;
    if (left)
        fetch_body(f, f->head.p + hl, left);
}

static void fetch_bytes(fetch_t *f, const uint8_t *d, size_t n)
{
    if (f->st == F_HEAD) {
        buf_add(&f->head, d, n);
        uint8_t *e = memmem(f->head.p, f->head.len, "\r\n\r\n", 4);
        if (!e) {
            if (f->head.len > 65536)
                fetch_end(f, 0, "response header too large");
            return;
        }
        fetch_parse_head(f, (size_t)(e - f->head.p + 4));
        return;
    }
    fetch_body(f, d, n);
}

static void fetch_eof(fetch_t *f, int err)
{
    if (f->st == F_HEAD) {
        fetch_end(f, 0, err ? "connection error" : "connection closed before response");
        return;
    }
    if (f->chunked || (f->clen >= 0 && f->remain > 0)) {
        fetch_end(f, 0, "body truncated");
        return;
    }
    fetch_end(f, !err, err ? "connection error" : NULL);
}

static ssize_t fetch_recv(fetch_t *f, uint8_t *b, size_t n)
{
    if (f->ssl) {
        int r = SSL_read(f->ssl, b, (int)n);
        if (r > 0)
            return r;
        int e = SSL_get_error(f->ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            errno = EAGAIN;
            return -1;
        }
        if (e == SSL_ERROR_ZERO_RETURN)
            return 0;
        if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0 && errno == 0)
            return 0;
        ERR_clear_error();
        errno = EIO;
        return -1;
    }
    return recv(f->ev.fd, b, n, 0);
}

static void fetch_read(fetch_t *f, int force)
{
    static uint8_t rb[65536];
    int loops = 0;
    while (!f->ev.dead && (!f->paused || force)) {
        errno = 0;
        ssize_t n = fetch_recv(f, rb, sizeof rb);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                if (force && !f->ssl)
                    fetch_eof(f, 1);
                return;
            }
            fetch_eof(f, 1);
            return;
        }
        if (n == 0) {
            fetch_eof(f, 0);
            return;
        }
        f->deadline = g_now + f->idle_to;
        fetch_bytes(f, rb, (size_t)n);
        if (!f->ssl && ++loops >= 4)
            return;
        if (force)
            force = 0;
    }
}

static int fetch_flush_req(fetch_t *f)
{
    while (f->req_off < f->req.len) {
        ssize_t n;
        if (f->ssl) {
            int r = SSL_write(f->ssl, f->req.p + f->req_off, (int)(f->req.len - f->req_off));
            if (r <= 0) {
                int e = SSL_get_error(f->ssl, r);
                if (e == SSL_ERROR_WANT_WRITE) {
                    ev_watch(&f->ev, EPOLLOUT);
                    return 0;
                }
                if (e == SSL_ERROR_WANT_READ) {
                    ev_watch(&f->ev, EPOLLIN);
                    return 0;
                }
                fetch_end(f, 0, "TLS write failed");
                return -1;
            }
            n = r;
        } else {
            n = send(f->ev.fd, f->req.p + f->req_off, f->req.len - f->req_off, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    ev_watch(&f->ev, EPOLLOUT);
                    return 0;
                }
                fetch_end(f, 0, "send failed");
                return -1;
            }
        }
        f->req_off += (size_t)n;
    }
    f->st = F_HEAD;
    f->deadline = g_now + f->idle_to;
    ev_watch(&f->ev, f->paused ? 0 : EPOLLIN);
    return 1;
}

static void fetch_on_event(fetch_t *f, uint32_t evs)
{
    if (f->st == F_CONN) {
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(f->ev.fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) {
            char m[96];
            snprintf(m, sizeof m, "connect failed: %s", strerror(err));
            fetch_end(f, 0, m);
            return;
        }
        if (f->https) {
            f->ssl = SSL_new(g_ssl);
            if (!f->ssl) {
                fetch_end(f, 0, "TLS init failed");
                return;
            }
            SSL_set_fd(f->ssl, f->ev.fd);
            struct in_addr tmp;
            if (inet_pton(AF_INET, f->host, &tmp) != 1)
                SSL_set_tlsext_host_name(f->ssl, f->host);
            SSL_set_connect_state(f->ssl);
            f->st = F_TLS;
        } else {
            f->st = F_SEND;
        }
    }
    if (f->st == F_TLS) {
        ERR_clear_error();
        int r = SSL_do_handshake(f->ssl);
        if (r != 1) {
            int e = SSL_get_error(f->ssl, r);
            if (e == SSL_ERROR_WANT_READ) {
                ev_watch(&f->ev, EPOLLIN);
                return;
            }
            if (e == SSL_ERROR_WANT_WRITE) {
                ev_watch(&f->ev, EPOLLOUT);
                return;
            }
            fetch_end(f, 0, "TLS handshake failed");
            return;
        }
        f->st = F_SEND;
    }
    if (f->st == F_SEND) {
        if (fetch_flush_req(f) <= 0)
            return;
    }
    if (f->st == F_HEAD || f->st == F_BODY)
        fetch_read(f, (evs & (EPOLLERR | EPOLLHUP)) && f->paused);
}

static void fetch_sweep(void)
{
    for (fetch_t *f = g_fetches, *nx; f; f = nx) {
        nx = f->gnext;
        if (f->ev.dead)
            continue;
        if (f->derr) {
            fetch_end(f, 0, f->derr);
            continue;
        }
        if (f->paused) {
            f->deadline = g_now + f->idle_to;
            continue;
        }
        if (f->ssl && f->st >= F_HEAD && SSL_pending(f->ssl) > 0) {
            fetch_read(f, 0);
            continue;
        }
        if (g_now > f->deadline)
            fetch_end(f, 0, f->st < F_HEAD ? "connect timeout" : "read timeout");
    }
}

/* -------------------------------------------------------------- MPEG-TS core */

static uint32_t g_crc_tab[256];

static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i << 24;
        for (int k = 0; k < 8; k++)
            c = (c & 0x80000000u) ? (c << 1) ^ 0x04C11DB7u : (c << 1);
        g_crc_tab[i] = c;
    }
}

static uint32_t crc32_mpeg(const uint8_t *d, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--)
        c = (c << 8) ^ g_crc_tab[((c >> 24) ^ *d++) & 0xFF];
    return c;
}

static void oseg_unref(oseg_t *s)
{
    if (s && --s->ref == 0) {
        free(s->data);
        free(s);
    }
}

channel_t *ch_find(const char *id)
{
    if (!id)
        return NULL;
    for (channel_t *c = g_channels; c; c = c->next)
        if (!strcmp(c->id, id))
            return c;
    return NULL;
}

static void ts_reset_psi(channel_t *ch)
{
    memset(ch->kind, 0, sizeof ch->kind);
    memset(ch->stype, 0, sizeof ch->stype);
    memset(ch->in_cc, -1, sizeof ch->in_cc);
    ch->ncaps = 0;
    ch->npmt = 0;
    ch->pcr_pid = -1;
    ch->cur_pcr = -1;
    ch->br_pcr0 = -1;
    ch->kf_cnt = 0;
    ch->synced = 0;
    ch->carry_n = 0;
}

static psicap_t *cap_for(channel_t *ch, int pid, int create)
{
    for (int i = 0; i < ch->ncaps; i++)
        if (ch->caps[i].pid == pid)
            return &ch->caps[i];
    if (!create || ch->ncaps >= 9)
        return NULL;
    psicap_t *c = &ch->caps[ch->ncaps++];
    memset(c, 0, sizeof *c);
    c->pid = pid;
    return c;
}

static int is_video_stype(int st)
{
    return st == 0x01 || st == 0x02 || st == 0x10 || st == 0x1B || st == 0x24 || st == 0x42 || st == 0xD1 ||
           st == 0xEA || st == 0x33;
}

static int is_audio_stype(int st)
{
    return st == 0x03 || st == 0x04 || st == 0x0F || st == 0x11 || st == 0x1C || st == 0x2D || st == 0x81 ||
           st == 0x82 || st == 0x83 || st == 0x84 || st == 0x87;
}

static void parse_pat(channel_t *ch, const uint8_t *s, int sl)
{
    int end = 3 + sl - 4;
    int npids[8], npnr[8], n = 0;
    for (int i = 8; i + 4 <= end && n < 8; i += 4) {
        int pnr = (s[i] << 8) | s[i + 1];
        int pid = ((s[i + 2] & 0x1F) << 8) | s[i + 3];
        if (pnr == 0)
            continue;
        npnr[n] = pnr;
        npids[n++] = pid;
    }
    for (int i = 0; i < ch->npmt; i++) {
        int keep = 0;
        for (int k = 0; k < n; k++)
            keep |= npids[k] == ch->pmt_pid[i];
        if (!keep && ch->kind[ch->pmt_pid[i]] == K_PMT)
            ch->kind[ch->pmt_pid[i]] = K_NONE;
    }
    ch->tsid = (s[3] << 8) | s[4];
    ch->npmt = n;
    for (int i = 0; i < n; i++) {
        ch->pmt_pid[i] = npids[i];
        ch->pnr[i] = npnr[i];
        ch->kind[npids[i]] = K_PMT;
    }
}

static void parse_pmt(channel_t *ch, const uint8_t *s, int sl)
{
    int end = 3 + sl - 4;
    if (end < 12)
        return;
    int pcr = ((s[8] & 0x1F) << 8) | s[9];
    int pil = ((s[10] & 0x0F) << 8) | s[11];
    if (pcr != 0x1FFF)
        ch->pcr_pid = pcr;
    for (int i = 12 + pil; i + 5 <= end;) {
        int st = s[i];
        int pid = ((s[i + 1] & 0x1F) << 8) | s[i + 2];
        int el = ((s[i + 3] & 0x0F) << 8) | s[i + 4];
        int kind = K_OTHER;
        if (is_video_stype(st))
            kind = K_VIDEO;
        else if (is_audio_stype(st))
            kind = K_AUDIO;
        else if (st == 0x06) {
            for (int d = i + 5; d + 2 <= i + 5 + el && d + 2 <= end; d += 2 + s[d + 1]) {
                int tag = s[d];
                if (tag == 0x6A || tag == 0x7A || tag == 0x7C || tag == 0x7F)
                    kind = K_AUDIO;
                if (tag == 0x05 && d + 6 <= end && (!memcmp(s + d + 2, "AC-3", 4) || !memcmp(s + d + 2, "EAC3", 4)))
                    kind = K_AUDIO;
            }
        }
        if (pid < 8191 && ch->kind[pid] != K_PMT) {
            ch->kind[pid] = (uint8_t)kind;
            ch->stype[pid] = (uint8_t)st;
        }
        i += 5 + el;
    }
}

static void psi_push(channel_t *ch, int pid, const uint8_t *p, int off, int pusi)
{
    psicap_t *c = cap_for(ch, pid, 1);
    if (!c || off >= TS)
        return;
    if (pusi) {
        int s = off + 1 + p[off];
        c->need = 0;
        if (s + 3 > TS)
            return;
        int sl = ((p[s + 1] & 0x0F) << 8) | p[s + 2];
        if (3 + sl > (int)sizeof c->sec || sl < 9)
            return;
        c->need = 3 + sl;
        int take = TS - s < c->need ? TS - s : c->need;
        memcpy(c->sec, p + s, (size_t)take);
        c->have = take;
        c->npk = 0;
        memcpy(c->pk[c->npk++], p, TS);
    } else if (c->need && c->have < c->need && c->npk < 4) {
        int take = TS - off < c->need - c->have ? TS - off : c->need - c->have;
        memcpy(c->sec + c->have, p + off, (size_t)take);
        c->have += take;
        memcpy(c->pk[c->npk++], p, TS);
    } else {
        return;
    }
    if (c->need && c->have >= c->need) {
        int sl = c->need - 3;
        if (crc32_mpeg(c->sec, (size_t)c->need) == 0) {
            if (pid == 0 && c->sec[0] == 0x00)
                parse_pat(ch, c->sec, sl);
            else if (c->sec[0] == 0x02)
                parse_pmt(ch, c->sec, sl);
            memcpy(c->done, c->pk, sizeof c->pk);
            c->ndone = c->npk;
        }
        c->need = 0;
    }
}

static int pes_is_kf(const uint8_t *p, int off, int st)
{
    if (off + 9 > TS || p[off] || p[off + 1] || p[off + 2] != 1)
        return 0;
    int i = off + 9 + p[off + 8];
    for (; i + 4 <= TS; i++) {
        if (p[i] || p[i + 1] || p[i + 2] != 1)
            continue;
        uint8_t b = p[i + 3];
        if (st == 0x24) {
            int t = (b >> 1) & 0x3F;
            if ((t >= 16 && t <= 21) || t == 32 || t == 33)
                return 1;
            if (t <= 9)
                return 0;
        } else if (st == 0x01 || st == 0x02) {
            if (b == 0xB3)
                return 1;
            if (b == 0x00)
                return 0;
        } else {
            int t = b & 0x1F;
            if (t == 7 || t == 5)
                return 1;
            if (t == 1 || t == 2 || t == 6)
                return 0;
        }
        i += 2;
    }
    return 0;
}

static int ts_packet(channel_t *ch, uint8_t *p, int hls, int *is_kf)
{
    int pid = ((p[1] & 0x1F) << 8) | p[2];
    if ((pid == 0x11 && ch->drop_sdt) || (pid == 0x12 && ch->drop_eit))
        return 0;
    ch->packets++;
    if (pid == 0x1FFF)
        return 1;
    int tei = p[1] & 0x80, pusi = p[1] & 0x40, scr = p[3] & 0xC0;
    int afc = (p[3] >> 4) & 3, cc = p[3] & 15;
    int off = 4, rai = 0, disc = 0;
    if (afc & 2) {
        int al = p[4];
        off = 5 + al;
        if (al > 0) {
            int fl = p[5];
            disc = fl & 0x80;
            rai = fl & 0x40;
            if ((fl & 0x10) && al >= 7) {
                int64_t base = ((int64_t)p[6] << 25) | (p[7] << 17) | (p[8] << 9) | (p[9] << 1) | (p[10] >> 7);
                int64_t pcr = base * 300 + (((p[10] & 1) << 8) | p[11]);
                if (ch->pcr_pid < 0)
                    ch->pcr_pid = pid;
                if (pid == ch->pcr_pid)
                    ch->cur_pcr = pcr;
            }
            if (disc && hls) {
                p[5] &= 0x7F;
                disc = 0;
            }
        }
        if (off > TS)
            off = TS;
    }
    if (tei) {
        ch->in_cc[pid] = -1;
        return 1;
    }
    if (afc & 1) {
        if (ch->in_cc[pid] >= 0 && !disc && cc != ((ch->in_cc[pid] + 1) & 15) && cc != ch->in_cc[pid])
            ch->cc_err++;
        ch->in_cc[pid] = (int8_t)cc;
        if (hls) {
            int o = ch->out_cc[pid] < 0 ? cc : ((ch->out_cc[pid] + 1) & 15);
            ch->out_cc[pid] = (int8_t)o;
            p[3] = (uint8_t)((p[3] & 0xF0) | o);
        }
    } else if (hls && ch->out_cc[pid] >= 0) {
        p[3] = (uint8_t)((p[3] & 0xF0) | ch->out_cc[pid]);
    }
    if (scr)
        ch->scr_win = 1;
    int kind = ch->kind[pid];
    if (!scr && (afc & 1) && (pid == 0 || kind == K_PMT))
        psi_push(ch, pid, p, off, pusi);
    if (pusi && !scr && (afc & 1) && off + 4 <= TS) {
        int startcode = p[off] == 0 && p[off + 1] == 0 && p[off + 2] == 1;
        if (kind == K_VIDEO || kind == K_AUDIO) {
            if (!startcode)
                ch->pes_err++;
        } else if (kind == K_NONE && startcode && pid > 0x1F && ch->npmt == 0) {
            int sid = p[off + 3];
            if (sid >= 0xE0 && sid <= 0xEF)
                ch->kind[pid] = (uint8_t)(kind = K_VIDEO);
            else if ((sid >= 0xC0 && sid <= 0xDF) || sid == 0xBD)
                ch->kind[pid] = (uint8_t)(kind = K_AUDIO);
        }
    }
    if (kind == K_VIDEO && !scr && (afc & 1) && ((pusi && pes_is_kf(p, off, ch->stype[pid])) || (rai && pusi && !ch->stype[pid])))
        *is_kf = 1;
    return 1;
}

/* ------------------------------------------------------------ channel ring */

static uint64_t ring_low(channel_t *ch)
{
    if (!ch->ring || ch->rcap <= 64 * TS)
        return ch->wpos;
    uint64_t room = ch->rcap - 64 * TS;
    return ch->wpos > room ? ch->wpos - room : 0;
}

static void ring_resize(channel_t *ch, size_t ncap)
{
    if (!ch->ring || !ch->rcap)
        return;
    ncap = ncap / TS * TS;
    if (ncap < TS * 64 || ncap == ch->rcap)
        return;
    uint8_t *nr = malloc(ncap);
    if (!nr)
        return;
    uint64_t keep = min_sz((size_t)min_sz((size_t)ch->wpos, ch->rcap), ncap);
    keep -= keep % TS;
    for (uint64_t p = ch->wpos - keep; p < ch->wpos;) {
        size_t so = (size_t)(p % ch->rcap), dso = (size_t)(p % ncap);
        size_t n = min_sz(min_sz(ch->rcap - so, ncap - dso), (size_t)(ch->wpos - p));
        memcpy(nr + dso, ch->ring + so, n);
        p += n;
    }
    free(ch->ring);
    ch->ring = nr;
    ch->rcap = ncap;
}

static void prefix_build(channel_t *ch, buf_t *b)
{
    psicap_t *pat = cap_for(ch, 0, 0);
    if (!pat || !pat->ndone)
        return;
    buf_add(b, pat->done, (size_t)pat->ndone * TS);
    for (int i = 0; i < ch->npmt; i++) {
        psicap_t *c = cap_for(ch, ch->pmt_pid[i], 0);
        if (c && c->ndone)
            buf_add(b, c->done, (size_t)c->ndone * TS);
    }
}

static void ring_copy(channel_t *ch, buf_t *dst, uint64_t from, uint64_t to)
{
    if (!ch->ring || !ch->rcap)
        return;
    while (from < to) {
        size_t o = (size_t)(from % ch->rcap);
        size_t n = min_sz(ch->rcap - o, (size_t)(to - from));
        buf_add(dst, ch->ring + o, n);
        from += n;
    }
}

/* ------------------------------------------------------------- HLS output */

static double seg_elapsed(channel_t *ch, int64_t pcr)
{
    if (pcr >= 0 && ch->cur_t0_pcr >= 0) {
        double d = ((pcr - ch->cur_t0_pcr + PCR_WRAP) % PCR_WRAP) / PCR_HZ;
        if (d >= 0 && d < 60)
            return d;
    }
    return g_now - ch->cur_t0_wall;
}

static void seg_begin(channel_t *ch, int64_t pcr, double wall)
{
    ch->cseg.len = 0;
    prefix_build(ch, &ch->cseg);
    ch->cur_t0_pcr = pcr;
    ch->cur_t0_wall = wall;
    ch->cur_started = 1;
    ch->cur_disc = ch->disc_pending;
    ch->disc_pending = 0;
}

static void seg_finish(channel_t *ch, double dur)
{
    if (ch->cseg.len < TS * 8)
        return;
    oseg_t *s = calloc(1, sizeof *s);
    if (!s)
        return;
    s->ref = 1;
    s->seq = ch->next_seq++;
    s->dur = dur > 0.05 ? dur : ch->seg_target;
    s->disc = ch->cur_disc;
    s->data = ch->cseg.p;
    s->len = ch->cseg.len;
    ch->cseg.p = NULL;
    ch->cseg.len = ch->cseg.cap = 0;
    int keep = g_now - ch->hls_last_req > 60.0 ? 3 : ch->seg_keep;
    while (ch->nsegs > 0 && (ch->nsegs == 16 || ch->nsegs >= keep)) {
        oseg_unref(ch->segs[0]);
        memmove(ch->segs, ch->segs + 1, (size_t)(ch->nsegs - 1) * sizeof ch->segs[0]);
        ch->nsegs--;
    }
    ch->segs[ch->nsegs++] = s;
}

static void hls_out_off(channel_t *ch)
{
    for (int i = 0; i < ch->nsegs; i++)
        oseg_unref(ch->segs[i]);
    ch->nsegs = 0;
    buf_free(&ch->cseg);
    ch->cur_started = 0;
    ch->hls_on = 0;
}

static void hls_out_feed(channel_t *ch, const uint8_t *s, size_t o, const size_t *kfo, const int64_t *kfp, int nk)
{
    if (!ch->hls_on)
        return;
    size_t run = 0;
    for (int k = 0; k < nk; k++) {
        if (!ch->cur_started) {
            run = kfo[k];
            seg_begin(ch, kfp[k], g_now);
            continue;
        }
        double d = seg_elapsed(ch, kfp[k]);
        double target = (ch->mode == IN_TS || ch->mode == IN_UDP)
                            ? (ch->nsegs < 2 ? 1.0 : fmin(1.5, ch->seg_target * 0.6))
                            : ch->seg_target * 0.72;
        if (d >= target) {
            buf_add(&ch->cseg, s + run, kfo[k] - run);
            seg_finish(ch, d);
            run = kfo[k];
            seg_begin(ch, kfp[k], g_now);
        }
    }
    if (!ch->cur_started)
        return;
    buf_add(&ch->cseg, s + run, o - run);
    double d = seg_elapsed(ch, ch->cur_pcr);
    if (d >= ch->seg_target * 3.0 || ch->cseg.len > 48u * 1024 * 1024) {
        seg_finish(ch, d);
        seg_begin(ch, ch->cur_pcr, g_now);
    }
}

static void hls_out_activate(channel_t *ch)
{
    ch->hls_on = 1;
    ch->cur_started = 0;
    ch->cseg.len = 0;
    uint64_t lo = ring_low(ch);
    int newest = -1, oldest = -1;
    for (int i = 0; i < ch->kf_cnt; i++) {
        int idx = (ch->kf_head - 1 - i + KF_N) % KF_N;
        if (ch->kf_pos[idx] < lo || ch->kf_pos[idx] >= ch->wpos)
            break;
        if (newest < 0)
            newest = idx;
        oldest = idx;
    }
    if (newest < 0)
        return;
    if (oldest != newest) {
        seg_begin(ch, ch->kf_pcr[oldest], ch->kf_wall[oldest]);
        ring_copy(ch, &ch->cseg, ch->kf_pos[oldest], ch->kf_pos[newest]);
        double d = -1;
        if (ch->kf_pcr[oldest] >= 0 && ch->kf_pcr[newest] >= 0)
            d = ((ch->kf_pcr[newest] - ch->kf_pcr[oldest] + PCR_WRAP) % PCR_WRAP) / PCR_HZ;
        if (d <= 0 || d > 60)
            d = ch->kf_wall[newest] - ch->kf_wall[oldest];
        if (d >= 0.3)
            seg_finish(ch, d);
    }
    seg_begin(ch, ch->kf_pcr[newest], ch->kf_wall[newest]);
    ring_copy(ch, &ch->cseg, ch->kf_pos[newest], ch->wpos);
}

/* --------------------------------------------------------------- TS feed */

static void udp_outs_push(channel_t *ch, const uint8_t *pk, int flush)
{
    for (int u = 0; u < ch->n_udp_outs; u++) {
        udp_out_t *uo = &ch->udp_outs[u];
        if (uo->fd < 0)
            continue;
        if (pk) {
            memcpy(uo->pkt + uo->n * TS, pk, TS);
            uo->n++;
        }
        if (uo->n >= 7 || (flush && uo->n > 0)) {
            sendto(uo->fd, uo->pkt, (size_t)uo->n * TS, MSG_NOSIGNAL,
                   (struct sockaddr *)&uo->addr, sizeof uo->addr);
            uo->n = 0;
        }
    }
}

static void ts_feed(channel_t *ch, const uint8_t *d, size_t n, int hls)
{
    if (!n || !ch->ring || !ch->rcap)
        return;
    ch->last_data = g_now;
    ch->win_bytes += n;
    g_scr.len = 0;
    buf_add(&g_scr, ch->carry, (size_t)ch->carry_n);
    buf_add(&g_scr, d, n);
    ch->carry_n = 0;
    uint8_t *s = g_scr.p;
    size_t len = g_scr.len, i = 0, o = 0;
    size_t kfo[64];
    int64_t kfp[64];
    int nk = 0;
    while (i + TS <= len) {
        if (s[i] != 0x47 || (!ch->synced && i + 2 * TS <= len && s[i + TS] != 0x47)) {
            if (ch->synced)
                ch->sync_losses++;
            ch->synced = 0;
            i++;
            continue;
        }
        ch->synced = 1;
        if (o != i)
            memmove(s + o, s + i, TS);
        int kf = 0;
        if (ts_packet(ch, s + o, hls, &kf)) {
            if (ch->n_udp_outs > 0)
                udp_outs_push(ch, s + o, 0);
            if (kf && nk < 64) {
                kfo[nk] = o;
                kfp[nk++] = ch->cur_pcr;
            }
            o += TS;
        }
        i += TS;
    }
    if (ch->n_udp_outs > 0)
        udp_outs_push(ch, NULL, 1);
    size_t rem = len - i;
    if (rem >= TS)
        rem = TS - 1;
    memcpy(ch->carry, s + len - rem, rem);
    ch->carry_n = (int)rem;
    if (!o)
        return;
    uint64_t base = ch->wpos;
    size_t w = o > ch->rcap ? ch->rcap : o;
    const uint8_t *src = s + (o - w);
    uint64_t p = base + (o - w);
    while (w) {
        size_t ro = (size_t)(p % ch->rcap);
        size_t m = min_sz(w, ch->rcap - ro);
        memcpy(ch->ring + ro, src, m);
        src += m;
        p += m;
        w -= m;
    }
    for (int k = 0; k < nk; k++) {
        if (ch->kf_cnt) {
            int prev = (ch->kf_head - 1 + KF_N) % KF_N;
            double iv = -1;
            if (kfp[k] >= 0 && ch->kf_pcr[prev] >= 0)
                iv = ((kfp[k] - ch->kf_pcr[prev] + PCR_WRAP) % PCR_WRAP) / PCR_HZ;
            if (iv < 0 || iv > 30)
                iv = g_now - ch->kf_wall[prev];
            if (iv > 0.2 && iv <= 30)
                ch->gop = iv > ch->gop ? iv : 0.95 * ch->gop + 0.05 * iv;
        }
        ch->kf_pos[ch->kf_head] = base + kfo[k];
        ch->kf_pcr[ch->kf_head] = kfp[k];
        ch->kf_wall[ch->kf_head] = g_now;
        ch->kf_head = (ch->kf_head + 1) % KF_N;
        if (ch->kf_cnt < KF_N)
            ch->kf_cnt++;
    }
    ch->wpos = base + o;
    if (ch->pcr_pid >= 0 && ch->cur_pcr >= 0) {
        if (ch->br_pcr0 < 0) {
            ch->br_pcr0 = ch->cur_pcr;
            ch->br_pos0 = ch->wpos;
        } else {
            double dt = ((ch->cur_pcr - ch->br_pcr0 + PCR_WRAP) % PCR_WRAP) / PCR_HZ;
            if (dt > 30 || dt < 0) {
                ch->br_pcr0 = -1;
            } else if (dt >= 2.0) {
                ch->pcr_bitrate = (double)(ch->wpos - ch->br_pos0) * 8.0 / dt;
                ch->br_pcr0 = ch->cur_pcr;
                ch->br_pos0 = ch->wpos;
            }
        }
    }
    hls_out_feed(ch, s, o, kfo, kfp, nk);
}

/* --------------------------------------------------------- front (HTTP/WS) */

static void front_free(void *p)
{
    front_t *fr = p;
    buf_free(&fr->in);
    buf_free(&fr->out);
    buf_free(&fr->pre);
    buf_free(&fr->ws_frag);
    free(fr);
}

static void ch_list_remove(front_t **head, front_t *fr)
{
    if (fr->cprev)
        fr->cprev->cnext = fr->cnext;
    else if (*head == fr)
        *head = fr->cnext;
    if (fr->cnext)
        fr->cnext->cprev = fr->cprev;
    fr->cnext = fr->cprev = NULL;
}

void front_close(front_t *fr)
{
    if (!fr || fr->ev.dead)
        return;
    fr->ev.dead = 1;
    if (fr->cfetch) {
        fr->cfetch->owner = NULL;
        fetch_cancel(fr->cfetch);
        fr->cfetch = NULL;
    }
    if (fr->mode == FR_WS) {
        ctl_ws_on_close(fr);
    } else if (fr->mode == FR_TS && fr->ch) {
        fr->ch->last_client_act = g_now;
        ch_list_remove(&fr->ch->clients, fr);
        fr->ch->nclients--;
        ctl_on_sess_del(fr);
    } else if (fr->mode == FR_WAIT && fr->ch) {
        fr->ch->last_client_act = g_now;
        ch_list_remove(&fr->ch->waiters, fr);
    }
    fr->ch = NULL;
    if (fr->seg) {
        oseg_unref(fr->seg);
        fr->seg = NULL;
    }
    ev_close(&fr->ev);
    if (fr->gprev)
        fr->gprev->gnext = fr->gnext;
    else if (g_fronts == fr)
        g_fronts = fr->gnext;
    if (fr->gnext)
        fr->gnext->gprev = fr->gprev;
    bury(front_free, fr);
}

void front_respond(front_t *fr, int code, const char *reason, const char *ctype, const char *extra,
                   const void *body, size_t blen, oseg_t *seg, int head_only)
{
    fr->mode = FR_RESP;
    fr->out.len = 0;
    fr->out_off = 0;
    size_t total = seg ? seg->len : blen;
    buf_fmt(&fr->out,
            "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nAccess-Control-Allow-Origin: *\r\n%s"
            "Connection: close\r\n\r\n",
            code, reason, ctype, total, extra ? extra : "");
    if (!head_only) {
        if (seg) {
            seg->ref++;
            fr->seg = seg;
            fr->seg_off = 0;
        } else if (body && blen > 0) {
            buf_add(&fr->out, body, blen);
        }
    }
    front_flush(fr);
}

void front_respond_status_raw(front_t *fr, int code, const char *reason,
                              const char *headers, const void *body, size_t blen)
{
    fr->mode = FR_RESP;
    fr->out.len = 0;
    fr->out_off = 0;
    buf_fmt(&fr->out,
            "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\n%sConnection: close\r\n\r\n",
            code, reason ? reason : "OK", blen, headers ? headers : "");
    if (body && blen > 0)
        buf_add(&fr->out, body, blen);
    front_flush(fr);
}

void front_error(front_t *fr, int code, const char *reason)
{
    char body[256];
    int n = snprintf(body, sizeof body, "{\"detail\":\"%s\"}", reason ? reason : "Error");
    front_respond(fr, code, reason ? reason : "Error", "application/json",
                  code == 503 ? "Retry-After: 1\r\n" : NULL, body, (size_t)n, NULL, 0);
}

void front_flush(front_t *fr)
{
    if (fr->ev.dead)
        return;
    for (;;) {
        struct iovec iov[2];
        int n = 0;
        if (fr->out_off < fr->out.len) {
            iov[n].iov_base = fr->out.p + fr->out_off;
            iov[n++].iov_len = fr->out.len - fr->out_off;
        }
        if (fr->seg && fr->seg_off < fr->seg->len) {
            iov[n].iov_base = fr->seg->data + fr->seg_off;
            iov[n++].iov_len = fr->seg->len - fr->seg_off;
        }
        if (!n)
            break;
        ssize_t w = writev(fr->ev.fd, iov, n);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ev_watch(&fr->ev, EPOLLOUT | (fr->mode == FR_WS ? EPOLLIN : 0));
                return;
            }
            front_close(fr);
            return;
        }
        size_t a = min_sz((size_t)w, fr->out.len - fr->out_off);
        fr->out_off += a;
        w -= (ssize_t)a;
        if (w && fr->seg)
            fr->seg_off += (size_t)w;
        fr->deadline = g_now + 60;
    }
    fr->out.len = 0;
    fr->out_off = 0;
    if (fr->mode == FR_RESP || fr->close_when_done) {
        front_close(fr);
        return;
    }
    if (fr->mode == FR_WS) {
        ev_watch(&fr->ev, EPOLLIN);
    }
}

/* ---- WebSocket RFC 6455 */

void ws_upgrade(front_t *fr, const char *accept_b64, int is_cluster, const char *cluster_host)
{
    fr->mode = FR_WS;
    fr->ws_is_cluster = is_cluster;
    fr->ws_authed = 0;
    fr->ws_admin = 0;
    fr->ws_login[0] = 0;
    snprintf(fr->ws_cluster_host, sizeof fr->ws_cluster_host, "%s", cluster_host ? cluster_host : "");
    fr->in.len = 0;
    fr->out.len = 0;
    fr->out_off = 0;
    fr->deadline = g_now + 300.0;
    buf_fmt(&fr->out,
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n",
            accept_b64);
    front_flush(fr);
}

static void ws_queue_frame(front_t *fr, uint8_t opcode, const void *payload, size_t len)
{
    if (!fr || fr->ev.dead || fr->mode != FR_WS)
        return;
    if (fr->out.len - fr->out_off > 4u * 1024 * 1024) {
        front_close(fr);
        return;
    }
    uint8_t hdr[10];
    size_t hl = 2;
    hdr[0] = (uint8_t)(0x80 | (opcode & 0x0F));
    if (len < 126) {
        hdr[1] = (uint8_t)len;
    } else if (len <= 65535) {
        hdr[1] = 126;
        hdr[2] = (uint8_t)((len >> 8) & 0xFF);
        hdr[3] = (uint8_t)(len & 0xFF);
        hl = 4;
    } else {
        hdr[1] = 127;
        uint64_t l64 = (uint64_t)len;
        for (int i = 0; i < 8; i++)
            hdr[2 + i] = (uint8_t)((l64 >> (56 - 8 * i)) & 0xFF);
        hl = 10;
    }
    buf_add(&fr->out, hdr, hl);
    if (payload && len > 0)
        buf_add(&fr->out, payload, len);
    front_flush(fr);
}

void ws_send_text(front_t *fr, const char *txt, size_t len)
{
    ws_queue_frame(fr, 0x1, txt, len);
}

void ws_send_close(front_t *fr, uint16_t code)
{
    if (!fr || fr->ev.dead || fr->mode != FR_WS)
        return;
    uint8_t p[2] = {(uint8_t)(code >> 8), (uint8_t)(code & 0xFF)};
    fr->close_when_done = 1;
    ws_queue_frame(fr, 0x8, p, 2);
}

static void ws_consume_frames(front_t *fr)
{
    while (!fr->ev.dead && fr->mode == FR_WS && fr->in.len >= 2) {
        uint8_t *b = fr->in.p;
        int fin = (b[0] >> 7) & 1;
        int op = b[0] & 0x0F;
        int masked = (b[1] >> 7) & 1;
        uint64_t plen = b[1] & 0x7F;
        size_t pos = 2;
        if (plen == 126) {
            if (fr->in.len < pos + 2)
                return;
            plen = ((uint64_t)b[pos] << 8) | b[pos + 1];
            pos += 2;
        } else if (plen == 127) {
            if (fr->in.len < pos + 8)
                return;
            plen = 0;
            for (int i = 0; i < 8; i++)
                plen = (plen << 8) | b[pos + i];
            pos += 8;
        }
        if (plen > 2u * 1024 * 1024) {
            ws_send_close(fr, 1009);
            return;
        }
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked) {
            if (fr->in.len < pos + 4)
                return;
            memcpy(mask, b + pos, 4);
            pos += 4;
        }
        if (fr->in.len < pos + (size_t)plen)
            return;
        uint8_t *payload = b + pos;
        if (masked) {
            for (size_t i = 0; i < (size_t)plen; i++)
                payload[i] ^= mask[i & 3];
        }
        size_t total_frame = pos + (size_t)plen;
        if (op == 0x8) {
            fr->close_when_done = 1;
            ws_queue_frame(fr, 0x8, plen >= 2 ? payload : NULL, plen >= 2 ? 2 : 0);
            return;
        } else if (op == 0x9) {
            ws_queue_frame(fr, 0xA, payload, (size_t)plen);
        } else if (op == 0xA) {
            /* pong */
        } else if (op == 0x1 || op == 0x2 || op == 0x0) {
            if (op != 0x0) {
                fr->ws_frag.len = 0;
                fr->ws_frag_op = (uint8_t)op;
            }
            if (fr->ws_frag.len + (size_t)plen <= 2u * 1024 * 1024)
                buf_add(&fr->ws_frag, payload, (size_t)plen);
            if (fin) {
                buf_add(&fr->ws_frag, "", 1);
                ctl_ws_on_message(fr, (const char *)fr->ws_frag.p, fr->ws_frag.len - 1);
                fr->ws_frag.len = 0;
            }
        }
        if (!fr->ev.dead)
            buf_drop(&fr->in, total_frame);
    }
}

/* ---- TS viewers */

static double kf_age(channel_t *ch, int idx)
{
    if (ch->kf_pcr[idx] >= 0 && ch->cur_pcr >= 0) {
        double d = ((ch->cur_pcr - ch->kf_pcr[idx] + PCR_WRAP) % PCR_WRAP) / PCR_HZ;
        if (d >= 0 && d < 60)
            return d;
    }
    return g_now - ch->kf_wall[idx];
}

#define START_BURST_S 3.5

static uint64_t pick_start(channel_t *ch)
{
    uint64_t lo = ring_low(ch);
    if (ch->wpos == 0)
        return 0;
    int64_t cand = -1;
    for (int i = 0; i < ch->kf_cnt; i++) {
        int idx = (ch->kf_head - 1 - i + KF_N) % KF_N;
        uint64_t p = ch->kf_pos[idx];
        if (p < lo || p >= ch->wpos)
            break;
        cand = (int64_t)p;
        if (kf_age(ch, idx) >= START_BURST_S)
            return p;
    }
    if (cand >= 0)
        return (uint64_t)cand;
    uint64_t back = min_sz((size_t)(ch->wpos - lo), 512 * 1024);
    back -= back % TS;
    return ch->wpos - back;
}

static void client_prefix(channel_t *ch, buf_t *pre, uint64_t start)
{
    size_t base = pre->len;
    prefix_build(ch, pre);
    size_t np = (pre->len - base) / TS;
    if (!np)
        return;
    int pids[16], ccs[16], found[16], npid = 0;
    for (size_t k = 0; k < np && npid < 16; k++) {
        uint8_t *p = pre->p + base + k * TS;
        int pid = ((p[1] & 0x1F) << 8) | p[2], dup = 0;
        for (int j = 0; j < npid; j++)
            dup |= pids[j] == pid;
        if (!dup) {
            pids[npid] = pid;
            found[npid++] = 0;
        }
    }
    int left = npid;
    for (uint64_t p = start; p + TS <= ch->wpos && p < start + 4u * 1024 * 1024 && left; p += TS) {
        const uint8_t *q = ch->ring + (p % ch->rcap);
        int pid = ((q[1] & 0x1F) << 8) | q[2];
        for (int j = 0; j < npid; j++)
            if (!found[j] && pids[j] == pid && (q[3] & 0x10)) {
                found[j] = 1;
                ccs[j] = q[3] & 15;
                left--;
            }
    }
    for (int j = 0; j < npid; j++) {
        if (!found[j])
            continue;
        int c = ccs[j];
        for (size_t k = np; k-- > 0;) {
            uint8_t *p = pre->p + base + k * TS;
            if ((((p[1] & 0x1F) << 8) | p[2]) == pids[j]) {
                c = (c - 1) & 15;
                p[3] = (uint8_t)((p[3] & 0xF0) | c);
            }
        }
    }
}

static void client_send(front_t *c)
{
    channel_t *ch = c->ch;
    if (!ch || c->ev.dead)
        return;
    if (c->wait_kf) {
        psicap_t *pat = cap_for(ch, 0, 0);
        int have_psi = pat && pat->ndone && ch->npmt > 0;
        if (!(ch->kf_cnt > 0 && have_psi) && g_now < c->kf_deadline) {
            size_t prelen = c->pre.len - c->pre_off;
            if (prelen) {
                ssize_t w = send(c->ev.fd, c->pre.p + c->pre_off, prelen, MSG_NOSIGNAL);
                if (w < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        c->blocked = 1;
                        ev_watch(&c->ev, EPOLLIN | EPOLLOUT);
                        return;
                    }
                    front_close(c);
                    return;
                }
                c->last_progress = g_now;
                c->pre_off += (size_t)w;
                if (c->pre_off >= c->pre.len) {
                    c->pre.len = 0;
                    c->pre_off = 0;
                }
            }
            c->blocked = 0;
            ev_watch(&c->ev, EPOLLIN);
            return;
        }
        c->wait_kf = 0;
        c->pos = pick_start(ch);
        client_prefix(ch, &c->pre, c->pos);
    }
    for (int it = 0; it < 8; it++) {
        uint64_t lo = ring_low(ch);
        if (c->pos < lo) {
            c->pos = pick_start(ch);
            c->pre.len = 0;
            c->pre_off = 0;
            client_prefix(ch, &c->pre, c->pos);
        }
        struct iovec iov[3];
        int n = 0;
        size_t prelen = c->pre.len - c->pre_off;
        if (prelen) {
            iov[n].iov_base = c->pre.p + c->pre_off;
            iov[n++].iov_len = prelen;
        }
        uint64_t avail = ch->wpos - c->pos;
        if (avail > 4u * 1024 * 1024)
            avail = 4u * 1024 * 1024;
        if (avail) {
            size_t a = (size_t)(c->pos % ch->rcap);
            size_t first = min_sz((size_t)avail, ch->rcap - a);
            iov[n].iov_base = ch->ring + a;
            iov[n++].iov_len = first;
            if (avail > first) {
                iov[n].iov_base = ch->ring;
                iov[n++].iov_len = (size_t)avail - first;
            }
        }
        if (!n) {
            c->blocked = 0;
            ev_watch(&c->ev, EPOLLIN);
            return;
        }
        ssize_t w = writev(c->ev.fd, iov, n);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->blocked = 1;
                ev_watch(&c->ev, EPOLLIN | EPOLLOUT);
                return;
            }
            front_close(c);
            return;
        }
        c->last_progress = g_now;
        size_t a = min_sz((size_t)w, prelen);
        c->pre_off += a;
        if (c->pre_off >= c->pre.len) {
            c->pre.len = 0;
            c->pre_off = 0;
        }
        c->pos += (size_t)w - a;
        if ((size_t)w < prelen + (size_t)avail) {
            c->blocked = 1;
            ev_watch(&c->ev, EPOLLIN | EPOLLOUT);
            return;
        }
    }
}

void ch_serve_ts(front_t *fr, channel_t *ch, const char *login)
{
    ch_wake(ch);
    fr->mode = FR_TS;
    fr->ch = ch;
    snprintf(fr->login, sizeof fr->login, "%s", login ? login : "");
    fr->pre.len = 0;
    fr->pre_off = 0;
    buf_str(&fr->pre, "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nCache-Control: no-store, no-cache, "
                      "must-revalidate\r\nPragma: no-cache\r\nAccept-Ranges: none\r\nAccess-Control-Allow-Origin: "
                      "*\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n");
    psicap_t *pat = cap_for(ch, 0, 0);
    if (ch->kf_cnt > 0 && pat && pat->ndone && ch->npmt > 0) {
        fr->wait_kf = 0;
        fr->pos = pick_start(ch);
        client_prefix(ch, &fr->pre, fr->pos);
    } else {
        fr->wait_kf = 1;
        fr->kf_deadline = g_now + 3.5;
        fr->pos = 0;
    }
    fr->cnext = ch->clients;
    if (ch->clients)
        ch->clients->cprev = fr;
    ch->clients = fr;
    ch->nclients++;
    fr->sess = ++g_sess_seq;
    fr->sess_start_wall = time(NULL);
    fr->sess_sdate_ms = (int64_t)fr->sess_start_wall * 1000LL;
    fr->last_progress = g_now;
    ctl_on_sess_add(fr, ch);
    client_send(fr);
}

static void send_playlist(front_t *fr, channel_t *ch)
{
    buf_t b = {0};
    double maxd = 1.0, start_off = 0.0;
    for (int i = 0; i < ch->nsegs; i++)
        if (ch->segs[i]->dur > maxd)
            maxd = ch->segs[i]->dur;
    int first_play = ch->nsegs > 3 ? ch->nsegs - 3 : 0;
    for (int i = first_play; i < ch->nsegs; i++)
        start_off += ch->segs[i]->dur;
    buf_fmt(&b, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:%lld\n",
            (int)ceil(maxd), ch->nsegs ? ch->segs[0]->seq : 0LL);
    if (ch->nsegs >= 2 && start_off > 0.5)
        buf_fmt(&b, "#EXT-X-START:TIME-OFFSET=-%.3f\n", start_off);
    for (int i = 0; i < ch->nsegs; i++) {
        oseg_t *s = ch->segs[i];
        if (s->disc && i > 0)
            buf_str(&b, "#EXT-X-DISCONTINUITY\n");
        buf_fmt(&b, "#EXTINF:%.3f,\n%ssegment-%lld.ts%s\n", s->dur, fr->hls_pre, s->seq, fr->hls_suf);
    }
    front_respond(fr, 200, "OK", "application/vnd.apple.mpegurl",
                  "Cache-Control: no-store, no-cache, must-revalidate\r\n", b.p, b.len, NULL, fr->head_only);
    buf_free(&b);
}

static void wait_remove(front_t *fr)
{
    if (fr->mode == FR_WAIT && fr->ch) {
        ch_list_remove(&fr->ch->waiters, fr);
        fr->ch = NULL;
    }
}

void ch_serve_hls(front_t *fr, channel_t *ch, const char *pre, const char *suf, int head_only)
{
    int was_idle = (ch->mode == IN_IDLE);
    ch_wake(ch);
    snprintf(fr->hls_pre, sizeof fr->hls_pre, "%s", pre ? pre : "");
    snprintf(fr->hls_suf, sizeof fr->hls_suf, "%s", suf ? suf : "");
    fr->head_only = head_only;
    ch->hls_last_req = g_now;
    if (!ch->hls_on)
        hls_out_activate(ch);
    if (ch->nsegs >= 3) {
        send_playlist(fr, ch);
        return;
    }
    fr->mode = FR_WAIT;
    fr->ch = ch;
    fr->wait_until = g_now + (was_idle || ch->wpos == 0 ? fmax(ch->seg_target * 3.0 + 6.0, 14.0) : ch->seg_target * 2.0 + 3.0);
    fr->cnext = ch->waiters;
    if (ch->waiters)
        ch->waiters->cprev = fr;
    ch->waiters = fr;
    ev_watch(&fr->ev, EPOLLIN);
}

void ch_serve_seg(front_t *fr, channel_t *ch, const char *seg_name, int head_only)
{
    ch_wake(ch);
    ch->hls_last_req = g_now;
    long long n = -1;
    if (seg_name && !strncmp(seg_name, "segment-", 8))
        n = atoll(seg_name + 8);
    for (int i = 0; i < ch->nsegs; i++) {
        if (ch->segs[i]->seq == n) {
            front_respond(fr, 200, "OK", "video/mp2t", "Cache-Control: public, max-age=60\r\n",
                          NULL, 0, ch->segs[i], head_only);
            return;
        }
    }
    front_error(fr, 404, "Segment not found or expired");
}

static void parse_front_request(front_t *fr)
{
    if (fr->mode == FR_HEAD) {
        uint8_t *e = memmem(fr->in.p, fr->in.len, "\r\n\r\n", 4);
        if (!e) {
            if (fr->in.len > 65536)
                front_error(fr, 431, "Request header too large");
            return;
        }
        size_t hl = (size_t)(e - fr->in.p + 4);
        int64_t clen = 0;
        char *h = (char *)fr->in.p;
        char *line = memchr(h, '\n', hl);
        while (line && (size_t)(line - h + 1) < hl) {
            line++;
            char *eol = memchr(line, '\n', hl - (size_t)(line - h));
            size_t ll = eol ? (size_t)(eol - line) : (hl - (size_t)(line - h));
            if (ll >= 16 && !strncasecmp(line, "content-length:", 15)) {
                clen = strtoll(line + 15, NULL, 10);
                if (clen < 0)
                    clen = 0;
            }
            if (ll >= 11 && !strncasecmp(line, "user-agent:", 11)) {
                const char *v = line + 11;
                while ((size_t)(v - line) < ll && (*v == ' ' || *v == '\t'))
                    v++;
                size_t vl = (size_t)(line + ll - v);
                if (vl && v[vl - 1] == '\r')
                    vl--;
                snprintf(fr->ua, sizeof fr->ua, "%.*s", (int)vl, v);
            }
            line = eol;
        }
        if (clen > 16 * 1024 * 1024) {
            front_error(fr, 413, "Payload too large");
            return;
        }
        fr->head_len = hl;
        fr->body_need = clen;
        fr->mode = FR_BODY;
        fr->deadline = g_now + 30.0;
    }
    if (fr->mode == FR_BODY) {
        if (fr->in.len < fr->head_len + (size_t)fr->body_need)
            return;
        fr->deadline = g_now + 60.0;
        ctl_http_handle(fr, fr->head_len, (size_t)fr->body_need);
    }
}

static void front_on_event(front_t *fr, uint32_t evs)
{
    if (fr->mode == FR_TS) {
        if (evs & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
            uint8_t tmp[4096];
            ssize_t n = recv(fr->ev.fd, tmp, sizeof tmp, 0);
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                front_close(fr);
                return;
            }
        }
        if (evs & EPOLLOUT)
            client_send(fr);
        return;
    }
    if (fr->mode == FR_WAIT || fr->mode == FR_RESP || fr->mode == FR_CFETCH) {
        if (evs & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
            uint8_t tmp[4096];
            ssize_t n = recv(fr->ev.fd, tmp, sizeof tmp, 0);
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                wait_remove(fr);
                front_close(fr);
                return;
            }
        }
        if ((evs & EPOLLOUT) && fr->mode == FR_RESP)
            front_flush(fr);
        return;
    }
    if (evs & EPOLLOUT)
        front_flush(fr);
    if (fr->ev.dead || !(evs & (EPOLLIN | EPOLLHUP | EPOLLERR)))
        return;
    uint8_t rb[65536];
    ssize_t n = recv(fr->ev.fd, rb, sizeof rb, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        front_close(fr);
        return;
    }
    if (n == 0) {
        front_close(fr);
        return;
    }
    if (fr->mode == FR_WS) {
        fr->deadline = g_now + 300.0;
        buf_add(&fr->in, rb, (size_t)n);
        ws_consume_frames(fr);
        return;
    }
    buf_add(&fr->in, rb, (size_t)n);
    parse_front_request(fr);
}

/* ------------------------------------------------------------- listeners */

typedef struct listener {
    ev_t ev;
    char host[64];
    int port;
    struct listener *next;
} listener_t;
static listener_t *g_listeners = NULL;

static int listen_open(const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char ps[16];
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host && *host ? host : NULL, ps, &hints, &res) || !res)
        return -1;
    int fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int one = 1;
    if (fd >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, 2048) < 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

int listener_has(int port)
{
    for (listener_t *l = g_listeners; l; l = l->next)
        if (l->port == port)
            return 1;
    return 0;
}

int listener_add(const char *host, int port)
{
    for (listener_t *l = g_listeners; l; l = l->next)
        if (l->port == port)
            return 0;
    int fd = listen_open(host, port);
    if (fd < 0) {
        ELOG("cannot listen on %s:%d: %s", host ? host : "0.0.0.0", port, strerror(errno));
        return -1;
    }
    listener_t *l = calloc(1, sizeof *l);
    l->ev.type = EV_LISTEN;
    l->ev.fd = fd;
    l->ev.obj = l;
    snprintf(l->host, sizeof l->host, "%s", host ? host : "0.0.0.0");
    l->port = port;
    l->next = g_listeners;
    g_listeners = l;
    ev_watch(&l->ev, EPOLLIN);
    return 0;
}

void listener_del(int port)
{
    for (listener_t **pp = &g_listeners; *pp; pp = &(*pp)->next)
        if ((*pp)->port == port) {
            listener_t *l = *pp;
            *pp = l->next;
            l->ev.dead = 1;
            ev_close(&l->ev);
            bury(free, l);
            return;
        }
}

static void on_accept(listener_t *l)
{
    for (int i = 0; i < 64; i++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept4(l->ev.fd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
            return;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        front_t *fr = calloc(1, sizeof *fr);
        if (!fr) {
            close(fd);
            continue;
        }
        fr->ev.type = EV_FRONT;
        fr->ev.fd = fd;
        fr->ev.obj = fr;
        fr->mode = FR_HEAD;
        fr->listen_port = l->port;
        fr->deadline = g_now + 20;
        if (ss.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, fr->ip, sizeof fr->ip);
        else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
                inet_ntop(AF_INET, &s6->sin6_addr.s6_addr[12], fr->ip, sizeof fr->ip);
            else
                inet_ntop(AF_INET6, &s6->sin6_addr, fr->ip, sizeof fr->ip);
        }
        fr->gnext = g_fronts;
        if (g_fronts)
            g_fronts->gprev = fr;
        g_fronts = fr;
        ev_watch(&fr->ev, EPOLLIN);
    }
}

/* ------------------------------------------------------------- HLS input */

typedef struct qseg {
    char *url, *key_url;
    double dur;
    long long seq;
    uint8_t iv[16];
    int iv_set;
    struct qseg *next;
} qseg_t;

typedef struct chunk {
    struct chunk *next;
    size_t len, off, cap;
    uint8_t d[];
} chunk_t;

typedef struct slot {
    struct slot *next;
    hls_t *h;
    fetch_t *f;
    qseg_t *q;
    chunk_t *ch_head, *ch_tail;
    size_t unconsumed, got;
    int64_t clen;
    int done, failed, need_key, fed;
    EVP_CIPHER_CTX *dec;
} slot_t;

struct hls {
    channel_t *ch;
    char master[4096], pl[4096];
    fetch_t *plf, *keyf;
    buf_t plbody, kbody;
    char key_fetch_url[4096];
    double next_poll, td, credit, last_pace;
    int first, pl_err, consec_err, burst_done;
    long long last_seq;
    qseg_t *qh, *qt;
    int qn;
    slot_t *sh, *st;
    int sn;
    uint64_t seen[256];
    int seen_i;
    double avg_bps;
    struct {
        char url[4096];
        uint8_t key[16];
        int ok;
    } keys[4];
    int key_i;
};

static void ch_input_fail(channel_t *ch, const char *msg);

static uint64_t fnv(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t seg_key(const char *url)
{
    const char *q = strchr(url, '?');
    if (!q)
        return fnv(url, strlen(url));
    if (q - url >= 3 && !strncasecmp(q - 3, ".ts", 3))
        return fnv(url, (size_t)(q - url));
    static const char *drop[] = {"token", "md5", "auth", "wmsauthsign", "expires", "vtoken", "signature",
                                 "hash", "key", NULL};
    uint64_t h = fnv(url, (size_t)(q - url));
    const char *p = q + 1;
    while (*p) {
        size_t n = strcspn(p, "&");
        size_t kl = strcspn(p, "=&");
        int skip = 0;
        for (int i = 0; drop[i]; i++)
            if (strlen(drop[i]) == kl && !strncasecmp(p, drop[i], kl))
                skip = 1;
        if (!skip)
            h ^= fnv(p, n) * 31;
        p += n;
        if (*p == '&')
            p++;
    }
    return h;
}

static int seen_has(hls_t *h, uint64_t k)
{
    for (int i = 0; i < 256; i++)
        if (h->seen[i] == k)
            return 1;
    return 0;
}

static void seen_add(hls_t *h, uint64_t k)
{
    h->seen[h->seen_i] = k;
    h->seen_i = (h->seen_i + 1) % 256;
}

static void qseg_free(qseg_t *q)
{
    if (!q)
        return;
    free(q->url);
    free(q->key_url);
    free(q);
}

static void slot_free(slot_t *s)
{
    fetch_cancel(s->f);
    while (s->ch_head) {
        chunk_t *c = s->ch_head;
        s->ch_head = c->next;
        free(c);
    }
    if (s->dec)
        EVP_CIPHER_CTX_free(s->dec);
    qseg_free(s->q);
    free(s);
}

static void hls_mem_free(void *p)
{
    hls_t *h = p;
    buf_free(&h->plbody);
    buf_free(&h->kbody);
    free(h);
}

static void hls_free(hls_t *h)
{
    if (!h)
        return;
    fetch_cancel(h->plf);
    fetch_cancel(h->keyf);
    h->plf = h->keyf = NULL;
    while (h->sh) {
        slot_t *s = h->sh;
        h->sh = s->next;
        slot_free(s);
    }
    h->st = NULL;
    h->sn = 0;
    while (h->qh) {
        qseg_t *q = h->qh;
        h->qh = q->next;
        qseg_free(q);
    }
    h->qt = NULL;
    h->qn = 0;
    bury(hls_mem_free, h);
}

static size_t hls_total(hls_t *h)
{
    size_t t = 0;
    for (slot_t *s = h->sh; s; s = s->next)
        t += s->unconsumed;
    return t;
}

static double hls_rate(hls_t *h)
{
    slot_t *s = h->sh;
    if (s && s->clen > 0 && s->q->dur > 0.2)
        return (double)s->clen / s->q->dur;
    if (h->avg_bps > 0)
        return h->avg_bps;
    if (h->ch->pcr_bitrate > 100000)
        return h->ch->pcr_bitrate / 8;
    return 500000;
}

static size_t hls_cap(hls_t *h)
{
    double bps = h->avg_bps > 0 ? h->avg_bps : hls_rate(h);
    double want = bps * (h->td + 2.0);
    return (size_t)clampd(want, 2.0 * 1024 * 1024, 16.0 * 1024 * 1024);
}

static void hls_check_pause(hls_t *h)
{
    int full = hls_total(h) >= hls_cap(h);
    for (slot_t *s = h->sh; s; s = s->next)
        if (s->f)
            fetch_pause(s->f, full && (s != h->sh || h->sn == 1));
}

static void slot_append(slot_t *s, const uint8_t *d, size_t n)
{
    while (n) {
        chunk_t *c = s->ch_tail;
        if (!c || c->len == c->cap) {
            size_t cap = 65536;
            c = malloc(sizeof *c + cap);
            if (!c)
                return;
            c->next = NULL;
            c->len = c->off = 0;
            c->cap = cap;
            if (s->ch_tail)
                s->ch_tail->next = c;
            else
                s->ch_head = c;
            s->ch_tail = c;
        }
        size_t t = min_sz(n, c->cap - c->len);
        memcpy(c->d + c->len, d, t);
        c->len += t;
        d += t;
        n -= t;
        s->unconsumed += t;
    }
}

static const uint8_t *key_get(hls_t *h, const char *url)
{
    for (int i = 0; i < 4; i++)
        if (h->keys[i].ok && !strcmp(h->keys[i].url, url))
            return h->keys[i].key;
    return NULL;
}

static void slot_start(hls_t *h, slot_t *s);
static void hls_pump(hls_t *h);

static void seg_head(fetch_t *f)
{
    slot_t *s = f->owner;
    s->clen = f->status == 200 ? f->clen : -1;
}

static void seg_data(fetch_t *f, const uint8_t *d, size_t n)
{
    slot_t *s = f->owner;
    if (f->status != 200 && f->status != 206)
        return;
    if (s->got + n > 96u * 1024 * 1024) {
        fetch_cancel(f);
        s->f = NULL;
        s->done = 1;
        return;
    }
    s->got += n;
    if (s->dec) {
        static uint8_t out[65536 + 32];
        while (n) {
            size_t t = min_sz(n, 65536);
            int ol = 0;
            EVP_DecryptUpdate(s->dec, out, &ol, d, (int)t);
            slot_append(s, out, (size_t)ol);
            d += t;
            n -= t;
        }
    } else {
        slot_append(s, d, n);
    }
    hls_check_pause(s->h);
}

static void seg_done(fetch_t *f, int ok, const char *err)
{
    slot_t *s = f->owner;
    hls_t *h = s->h;
    channel_t *ch = h->ch;
    s->f = NULL;
    s->done = 1;
    if (s->dec && f->status == 200) {
        uint8_t out[64];
        int ol = 0;
        if (EVP_DecryptFinal_ex(s->dec, out, &ol) == 1)
            slot_append(s, out, (size_t)ol);
    }
    if (f->status == 404 || f->status == 410) {
        if (f->status == 410 && strcmp(h->pl, h->master))
            snprintf(h->pl, sizeof h->pl, "%s", h->master);
        return;
    }
    if (f->status == 401 || f->status == 403) {
        if (strcmp(h->pl, h->master)) {
            snprintf(h->pl, sizeof h->pl, "%s", h->master);
            h->next_poll = g_now;
        }
    }
    if (f->status == 200 && s->got >= TS) {
        if (s->q->dur > 0.2) {
            double m = (double)s->got / s->q->dur;
            h->avg_bps = h->avg_bps > 0 ? 0.7 * h->avg_bps + 0.3 * m : m;
        }
        h->consec_err = 0;
        return;
    }
    s->failed = 1;
    ch->input_errors++;
    if (f->status && f->status != 200)
        snprintf(ch->last_error, sizeof ch->last_error, "segment HTTP %d", f->status);
    else
        snprintf(ch->last_error, sizeof ch->last_error, "segment: %s", err ? err : "empty");
    (void)ok;
    if (++h->consec_err >= 10)
        ch_input_fail(ch, ch->last_error);
}

static const fetch_cb_t g_seg_cb = {seg_head, seg_data, seg_done};

static void key_head(fetch_t *f) { (void)f; }
static void key_data(fetch_t *f, const uint8_t *d, size_t n)
{
    hls_t *h = f->owner;
    if (h->kbody.len + n <= 64)
        buf_add(&h->kbody, d, n);
}

static void key_done(fetch_t *f, int ok, const char *err)
{
    (void)err;
    hls_t *h = f->owner;
    h->keyf = NULL;
    int good = ok && f->status == 200 && h->kbody.len == 16;
    if (good) {
        int i = h->key_i;
        h->key_i = (h->key_i + 1) % 4;
        snprintf(h->keys[i].url, sizeof h->keys[i].url, "%s", h->key_fetch_url);
        memcpy(h->keys[i].key, h->kbody.p, 16);
        h->keys[i].ok = 1;
    }
    h->kbody.len = 0;
    for (slot_t *s = h->sh; s; s = s->next) {
        if (!s->need_key)
            continue;
        if (good || strcmp(s->q->key_url, h->key_fetch_url)) {
            s->need_key = 0;
            slot_start(h, s);
        } else {
            s->need_key = 0;
            s->done = s->failed = 1;
        }
        if (!h->ch->hls || h->ch->hls != h)
            return;
    }
}

static const fetch_cb_t g_key_cb = {key_head, key_data, key_done};

static void slot_start(hls_t *h, slot_t *s)
{
    channel_t *ch = h->ch;
    qseg_t *q = s->q;
    if (q->key_url) {
        const uint8_t *k = key_get(h, q->key_url);
        if (!k) {
            s->need_key = 1;
            if (!h->keyf) {
                snprintf(h->key_fetch_url, sizeof h->key_fetch_url, "%s", q->key_url);
                h->kbody.len = 0;
                h->keyf = fetch_start(q->key_url, ch->ua, &g_key_cb, h, 8, 10);
            }
            return;
        }
        uint8_t iv[16];
        if (q->iv_set)
            memcpy(iv, q->iv, 16);
        else {
            memset(iv, 0, 16);
            for (int i = 0; i < 8; i++)
                iv[15 - i] = (uint8_t)((unsigned long long)q->seq >> (8 * i));
        }
        s->dec = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(s->dec, EVP_aes_128_cbc(), NULL, k, iv);
    }
    double idle = clampd(h->td * 1.5 + 2.0, 5.0, 20.0);
    s->f = fetch_start(q->url, ch->ua, &g_seg_cb, s, 8.0, idle);
    if (!s->f)
        s->done = s->failed = 1;
}

static void hls_pump(hls_t *h)
{
    while (h->sn < g_hls_parallel && h->qh) {
        if (h->sn >= 1 && hls_total(h) >= hls_cap(h))
            break;
        qseg_t *q = h->qh;
        h->qh = q->next;
        if (!h->qh)
            h->qt = NULL;
        h->qn--;
        q->next = NULL;
        slot_t *s = calloc(1, sizeof *s);
        if (!s) {
            qseg_free(q);
            continue;
        }
        s->h = h;
        s->q = q;
        s->clen = -1;
        if (h->st)
            h->st->next = s;
        else
            h->sh = s;
        h->st = s;
        h->sn++;
        slot_start(h, s);
        if (h->ch->hls != h)
            return;
    }
}

static void pl_head(fetch_t *f) { (void)f; }
static void pl_data(fetch_t *f, const uint8_t *d, size_t n)
{
    hls_t *h = f->owner;
    if (h->plbody.len + n < 16u * 1024 * 1024)
        buf_add(&h->plbody, d, n);
}

static void hls_parse(hls_t *h, char *text, const char *base);

static void hls_pl_error(hls_t *h, const char *msg, int status)
{
    channel_t *ch = h->ch;
    ch->input_errors++;
    if (status)
        snprintf(ch->last_error, sizeof ch->last_error, "playlist HTTP %d", status);
    else
        snprintf(ch->last_error, sizeof ch->last_error, "playlist: %s", msg);
    if (strcmp(h->pl, h->master))
        snprintf(h->pl, sizeof h->pl, "%s", h->master);
    h->pl_err++;
    if (h->first || h->pl_err >= 10) {
        ch_input_fail(ch, ch->last_error);
        return;
    }
    h->next_poll = g_now + fmin(2.0, 0.3 * h->pl_err);
}

static void pl_done(fetch_t *f, int ok, const char *err)
{
    hls_t *h = f->owner;
    h->plf = NULL;
    if (!ok || f->status != 200) {
        hls_pl_error(h, err ? err : "failed", f->status != 200 ? f->status : 0);
        return;
    }
    buf_add(&h->plbody, "", 1);
    hls_parse(h, (char *)h->plbody.p, f->url);
}

static const fetch_cb_t g_pl_cb = {pl_head, pl_data, pl_done};

static int attr_get(const char *line, const char *name, char *out, size_t outsz)
{
    size_t nl = strlen(name);
    for (const char *p = line; (p = strcasestr(p, name)); p += nl) {
        if (p > line && p[-1] != ',' && p[-1] != ':' && p[-1] != ' ')
            continue;
        if (p[nl] != '=')
            continue;
        const char *v = p + nl + 1;
        size_t n;
        if (*v == '"') {
            v++;
            n = strcspn(v, "\"");
        } else
            n = strcspn(v, ",\r\n");
        snprintf(out, outsz, "%.*s", (int)n, v);
        return 1;
    }
    return 0;
}

typedef struct {
    char *uri, *key;
    double dur;
    long long seq;
    uint8_t iv[16];
    int ivset;
} ent_t;

static void hls_parse(hls_t *h, char *text, const char *base)
{
    channel_t *ch = h->ch;
    while (*text == ' ' || *text == '\r' || *text == '\n' || *text == '\t' || (uint8_t)*text == 0xEF ||
           (uint8_t)*text == 0xBB || (uint8_t)*text == 0xBF)
        text++;
    if (strncmp(text, "#EXTM3U", 7)) {
        hls_pl_error(h, "not an M3U8 playlist", 0);
        return;
    }
    if (strstr(text, "#EXT-X-STREAM-INF")) {
        long best = -1;
        char best_uri[4096] = "";
        int pending = 0;
        long bw = 0;
        for (char *line = strtok(text, "\r\n"); line; line = strtok(NULL, "\r\n")) {
            while (*line == ' ')
                line++;
            if (!strncmp(line, "#EXT-X-STREAM-INF", 17)) {
                char v[64];
                bw = attr_get(line, "BANDWIDTH", v, sizeof v) ? atol(v) : 0;
                pending = 1;
            } else if (pending && *line && *line != '#') {
                if (bw > best) {
                    best = bw;
                    snprintf(best_uri, sizeof best_uri, "%s", line);
                }
                pending = 0;
            }
        }
        if (!best_uri[0]) {
            hls_pl_error(h, "master playlist without variants", 0);
            return;
        }
        char u[4096];
        url_resolve(base, best_uri, u, sizeof u);
        snprintf(h->pl, sizeof h->pl, "%s", u);
        h->next_poll = g_now;
        if (!h->plf) {
            h->plbody.len = 0;
            h->plf = fetch_start(h->pl, h->ch->ua, &g_pl_cb, h, 8.0, 10.0);
        }
        return;
    }
    ent_t ring[16];
    memset(ring, 0, sizeof ring);
    long long cnt = 0, mseq = 0;
    int have_mseq = 0;
    double td = 0, dur = -1;
    char keyu[4096] = "";
    uint8_t iv[16];
    memset(iv, 0, sizeof iv);
    int ivset = 0;
    for (char *line = strtok(text, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (!*line)
            continue;
        if (line[0] == '#') {
            if (!strncmp(line, "#EXT-X-TARGETDURATION:", 22))
                td = atof(line + 22);
            else if (!strncmp(line, "#EXT-X-MEDIA-SEQUENCE:", 22)) {
                mseq = atoll(line + 22);
                have_mseq = 1;
            } else if (!strncmp(line, "#EXTINF:", 8))
                dur = atof(line + 8);
            else if (!strncmp(line, "#EXT-X-KEY:", 11)) {
                char m[32] = "", uri[4096] = "", ivs[64] = "";
                attr_get(line, "METHOD", m, sizeof m);
                if (!strcasecmp(m, "AES-128") && attr_get(line, "URI", uri, sizeof uri)) {
                    url_resolve(base, uri, keyu, sizeof keyu);
                    ivset = 0;
                    if (attr_get(line, "IV", ivs, sizeof ivs) && (ivs[1] == 'x' || ivs[1] == 'X') &&
                        strlen(ivs) >= 34) {
                        for (int i = 0; i < 16; i++) {
                            unsigned v = 0;
                            sscanf(ivs + 2 + 2 * i, "%2x", &v);
                            iv[i] = (uint8_t)v;
                        }
                        ivset = 1;
                    }
                } else {
                    keyu[0] = 0;
                }
            }
            continue;
        }
        ent_t *e = &ring[cnt % 16];
        if (cnt >= 16)
            free(e->key);
        e->uri = line;
        e->dur = dur;
        e->seq = mseq + cnt;
        e->key = keyu[0] ? strdup(keyu) : NULL;
        memcpy(e->iv, iv, 16);
        e->ivset = ivset;
        cnt++;
        dur = -1;
    }
    if (td > 0)
        h->td = td;
    int n = cnt < 16 ? (int)cnt : 16;
    ent_t list[16];
    for (int i = 0; i < n; i++)
        list[i] = ring[(cnt - n + i) % 16];
    int isnew[16], nnew = 0;
    if (have_mseq && n && h->last_seq >= 0 && list[n - 1].seq < h->last_seq - 50)
        h->last_seq = -1;
    for (int i = 0; i < n; i++) {
        char u[4096];
        url_resolve(base, list[i].uri, u, sizeof u);
        uint64_t k = seg_key(u);
        isnew[i] = have_mseq ? list[i].seq > h->last_seq : !seen_has(h, k);
        if (isnew[i] && !have_mseq && seen_has(h, k))
            isnew[i] = 0;
        nnew += isnew[i];
    }
    int limit = h->first ? (h->td <= 5.0 ? 4 : 3) : (h->td <= 6.0 ? 3 : 2);
    int skip = nnew > limit ? nnew - limit : 0;
    h->first = 0;
    int added = 0;
    for (int i = 0; i < n; i++) {
        if (!isnew[i])
            continue;
        char u[4096];
        url_resolve(base, list[i].uri, u, sizeof u);
        seen_add(h, seg_key(u));
        if (list[i].seq > h->last_seq)
            h->last_seq = list[i].seq;
        if (skip > 0) {
            skip--;
            continue;
        }
        if (h->qn >= 24)
            continue;
        qseg_t *q = calloc(1, sizeof *q);
        if (!q)
            continue;
        q->url = strdup(u);
        q->key_url = list[i].key ? strdup(list[i].key) : NULL;
        q->dur = list[i].dur > 0 ? list[i].dur : h->td;
        q->seq = list[i].seq;
        memcpy(q->iv, list[i].iv, 16);
        q->iv_set = list[i].ivset;
        if (h->qt)
            h->qt->next = q;
        else
            h->qh = q;
        h->qt = q;
        h->qn++;
        added++;
    }
    for (int i = 0; i < 16 && i < cnt; i++)
        free(ring[i].key);
    h->pl_err = 0;
    double td2 = h->td > 0 ? h->td : 6.0;
    h->next_poll = g_now + (added ? clampd(td2 * 0.42, 0.3, 1.8) : clampd(td2 * 0.22, 0.4, 1.1));
    (void)ch;
    hls_pump(h);
}

static void hls_start(channel_t *ch, const char *master, const char *pl, char *body)
{
    hls_t *h = calloc(1, sizeof *h);
    if (!h) {
        ch_input_fail(ch, "out of memory");
        return;
    }
    h->ch = ch;
    snprintf(h->master, sizeof h->master, "%s", master);
    snprintf(h->pl, sizeof h->pl, "%s", pl);
    h->first = 1;
    h->last_seq = -1;
    h->td = 6.0;
    h->last_pace = g_now;
    h->next_poll = g_now;
    ch->hls = h;
    ch->mode = IN_HLS;
    if (body)
        hls_parse(h, body, pl);
}

static void hls_pace(hls_t *h)
{
    channel_t *ch = h->ch;
    double dt = g_now - h->last_pace;
    h->last_pace = g_now;
    dt = clampd(dt, 0, 0.5);
    double bps = hls_rate(h);
    size_t total = hls_total(h);
    double buf_sec = (double)total / bps;
    double hi = fmax(5.5, h->td + 1.0), mid = fmax(3.0, h->td * 0.65);
    double factor = buf_sec > hi ? 1.06 : buf_sec > mid ? 1.025 : 1.005;
    if (!h->burst_done) {
        if (ch->nsegs < 3) {
            h->credit = (double)total + 65536.0;
        } else {
            h->burst_done = 1;
            h->credit = fmin(bps * 0.5, 1.5 * 1024 * 1024);
        }
    } else {
        h->credit += dt * bps * factor;
    }
    double cap = fmax(bps * 0.3, 65536.0);
    while (h->sh) {
        if (!h->burst_done && ch->nsegs >= 3) {
            h->burst_done = 1;
            h->credit = fmin(bps * 0.4, 1.0 * 1024 * 1024);
            break;
        }
        slot_t *s = h->sh;
        chunk_t *c = s->ch_head;
        if (!c) {
            if (s->done && !s->need_key) {
                h->sh = s->next;
                if (!h->sh)
                    h->st = NULL;
                h->sn--;
                slot_free(s);
                continue;
            }
            break;
        }
        size_t avail = c->len - c->off;
        size_t want = h->credit > 0 ? (size_t)h->credit : 0;
        want -= want % TS;
        if (!want)
            break;
        if (!s->fed) {
            s->fed = 1;
            memset(ch->in_cc, -1, sizeof ch->in_cc);
        }
        size_t nfeed = min_sz(avail, want);
        ts_feed(ch, c->d + c->off, nfeed, 1);
        c->off += nfeed;
        s->unconsumed -= nfeed;
        h->credit -= (double)nfeed;
        if (c->off >= c->len) {
            s->ch_head = c->next;
            if (!s->ch_head)
                s->ch_tail = NULL;
            free(c);
        }
    }
    if (h->credit > cap && hls_total(h) == 0)
        h->credit = cap;
    if (h->credit < 0)
        h->credit = 0;
    hls_check_pause(h);
    hls_pump(h);
}

static void hls_tick(hls_t *h)
{
    if (!h->plf && g_now >= h->next_poll) {
        if (h->qn >= 6) {
            h->next_poll = g_now + 0.25;
        } else {
            h->plbody.len = 0;
            h->plf = fetch_start(h->pl, h->ch->ua, &g_pl_cb, h, 8.0, 10.0);
            if (!h->plf) {
                hls_pl_error(h, "bad URL", 0);
                return;
            }
        }
    }
    if (h->ch->hls != h)
        return;
    hls_pace(h);
}

/* --------------------------------------------------------------- UDP/RTP */

static int parse_udp_spec(const char *url, int *is_rtp, char *local_ip, size_t lsz,
                          char *host_ip, size_t hsz, int *port)
{
    const char *p = url;
    if (!strncasecmp(p, "udp://", 6)) {
        *is_rtp = 0;
        p += 6;
    } else if (!strncasecmp(p, "rtp://", 6)) {
        *is_rtp = 1;
        p += 6;
    } else
        return -1;
    local_ip[0] = 0;
    const char *end = p + strcspn(p, "/?#");
    const char *at = memchr(p, '@', (size_t)(end - p));
    if (at) {
        size_t ll = (size_t)(at - p);
        if (ll >= lsz)
            ll = lsz - 1;
        memcpy(local_ip, p, ll);
        local_ip[ll] = 0;
        p = at + 1;
    }
    const char *colon = memchr(p, ':', (size_t)(end - p));
    if (!colon)
        return -1;
    size_t hl = (size_t)(colon - p);
    if (hl == 0 || hl >= hsz)
        return -1;
    memcpy(host_ip, p, hl);
    host_ip[hl] = 0;
    *port = atoi(colon + 1);
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}

static void udp_in_free(void *p)
{
    free(p);
}

static void udp_in_stop(channel_t *ch)
{
    if (!ch->udpin)
        return;
    udp_in_t *u = ch->udpin;
    ch->udpin = NULL;
    u->ev.dead = 1;
    ev_close(&u->ev);
    bury(udp_in_free, u);
}

static void udp_in_on_event(udp_in_t *u)
{
    channel_t *ch = u->ch;
    if (!ch || u->ev.dead)
        return;
    static uint8_t pkt[65536];
    for (int i = 0; i < 64; i++) {
        ssize_t n = recv(u->ev.fd, pkt, sizeof pkt, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            return;
        }
        if (n == 0)
            continue;
        const uint8_t *d = pkt;
        size_t dl = (size_t)n;
        if (u->is_rtp && dl >= 12) {
            int cc = d[0] & 0x0F;
            int has_ext = (d[0] >> 4) & 1;
            int has_pad = (d[0] >> 5) & 1;
            size_t off = 12 + (size_t)cc * 4;
            if (has_ext && off + 4 <= dl) {
                uint16_t ext_words = (uint16_t)((d[off + 2] << 8) | d[off + 3]);
                off += 4 + (size_t)ext_words * 4;
            }
            if (has_pad && dl > off) {
                uint8_t pad = d[dl - 1];
                if (pad <= dl - off)
                    dl -= pad;
            }
            if (off < dl) {
                d += off;
                dl -= off;
            } else {
                continue;
            }
        }
        ts_feed(ch, d, dl, 0);
    }
}

static int udp_in_start(channel_t *ch, const char *url)
{
    int is_rtp = 0, port = 0;
    char lip[64], gip[64];
    if (parse_udp_spec(url, &is_rtp, lip, sizeof lip, gip, sizeof gip, &port) < 0)
        return -1;
    struct in_addr ga, la;
    if (inet_pton(AF_INET, gip, &ga) != 1)
        return -1;
    la.s_addr = htonl(INADDR_ANY);
    if (lip[0] && inet_pton(AF_INET, lip, &la) != 1)
        la.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof rbuf);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    uint32_t hip = ntohl(ga.s_addr);
    int is_mcast = (hip >= 0xE0000000u && hip <= 0xEFFFFFFFu);
    sa.sin_addr = is_mcast ? ga : (lip[0] ? la : ga);
    if (!is_mcast && !lip[0])
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    if (is_mcast) {
        struct ip_mreq mreq;
        mreq.imr_multiaddr = ga;
        mreq.imr_interface = la;
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq) < 0) {
            close(fd);
            return -1;
        }
    }
    udp_in_t *u = calloc(1, sizeof *u);
    if (!u) {
        close(fd);
        return -1;
    }
    u->ev.type = EV_UDP_IN;
    u->ev.fd = fd;
    u->ev.obj = u;
    u->ch = ch;
    u->is_rtp = is_rtp;
    ch->udpin = u;
    ch->mode = IN_UDP;
    ev_watch(&u->ev, EPOLLIN);
    return 0;
}

/* ---------------------------------------------------------------- inputs */

static void ch_input_stop(channel_t *ch)
{
    fetch_cancel(ch->tsf);
    ch->tsf = NULL;
    udp_in_stop(ch);
    if (ch->hls) {
        hls_t *h = ch->hls;
        ch->hls = NULL;
        hls_free(h);
    }
    buf_free(&ch->probe);
    ch->mode = IN_WAIT;
}

static void ch_input_fail(channel_t *ch, const char *msg)
{
    if (msg && msg != ch->last_error)
        snprintf(ch->last_error, sizeof ch->last_error, "%s", msg);
    ELOG("%s: input %d failed: %s", ch->id, ch->cur + 1, ch->last_error);
    ch_input_stop(ch);
    ch->fails_row++;
    int next = (ch->cur + 1) % ch->nurls;
    if (next != ch->cur) {
        ts_reset_psi(ch);
        memset(ch->out_cc, -1, sizeof ch->out_cc);
        ch->disc_pending = 1;
    } else {
        ch->carry_n = 0;
        ch->synced = 0;
        memset(ch->in_cc, -1, sizeof ch->in_cc);
    }
    ch->cur = next;
    ch->retry_at = g_now + (ch->fails_row >= ch->nurls ? 2.0 : 0.5);
}

static void ts_in_head(fetch_t *f)
{
    channel_t *ch = f->owner;
    if (f->status == 200 && strcasestr(f->ctype, "mpegurl"))
        ch->probe_m3u = 1;
}

static void ts_in_data(fetch_t *f, const uint8_t *d, size_t n)
{
    channel_t *ch = f->owner;
    if (f->status != 200)
        return;
    if (!ch->ts_checked) {
        ch->ts_checked = 1;
        size_t i = 0;
        while (i < n && (d[i] == ' ' || d[i] == '\r' || d[i] == '\n' || d[i] == 0xEF || d[i] == 0xBB ||
                         d[i] == 0xBF))
            i++;
        if (n - i >= 7 && !memcmp(d + i, "#EXTM3U", 7))
            ch->probe_m3u = 1;
    }
    if (ch->probe_m3u) {
        if (ch->probe.len + n > 16u * 1024 * 1024) {
            ch_input_fail(ch, "playlist too large");
            return;
        }
        buf_add(&ch->probe, d, n);
        return;
    }
    ts_feed(ch, d, n, 0);
}

static void ts_in_done(fetch_t *f, int ok, const char *err)
{
    channel_t *ch = f->owner;
    ch->tsf = NULL;
    if (f->status && f->status != 200) {
        char m[64];
        snprintf(m, sizeof m, "HTTP %d", f->status);
        ch->input_errors++;
        ch_input_fail(ch, m);
        return;
    }
    if (ch->probe_m3u && ch->probe.len) {
        buf_add(&ch->probe, "", 1);
        char *body = (char *)ch->probe.p;
        ch->probe.p = NULL;
        ch->probe.len = ch->probe.cap = 0;
        char master[4096];
        snprintf(master, sizeof master, "%s", ch->urls[ch->cur]);
        master[strcspn(master, "#")] = 0;
        hls_start(ch, master, f->url, body);
        free(body);
        return;
    }
    ch->input_errors++;
    ch_input_fail(ch, err ? err : (ok ? "stream ended" : "stream error"));
}

static const fetch_cb_t g_ts_cb = {ts_in_head, ts_in_data, ts_in_done};

static void ch_input_start(channel_t *ch)
{
    if (!ch->nurls)
        return;
    char url[4096];
    snprintf(url, sizeof url, "%s", ch->urls[ch->cur]);
    char *hash = strchr(url, '#');
    snprintf(ch->ua, sizeof ch->ua, "AstraG/2.0");
    ch->drop_sdt = ch->drop_eit = 0;
    if (hash) {
        *hash = 0;
        for (char *opt = strtok(hash + 1, "&"); opt; opt = strtok(NULL, "&")) {
            if (!strncmp(opt, "ua=", 3))
                snprintf(ch->ua, sizeof ch->ua, "%s", opt + 3);
            else if (!strcmp(opt, "no_sdt"))
                ch->drop_sdt = 1;
            else if (!strcmp(opt, "no_eit"))
                ch->drop_eit = 1;
        }
    }
    ch->in_started = g_now;
    ch->last_data = g_now;
    ch->ts_checked = 0;
    ch->probe_m3u = 0;
    ch->probe.len = 0;

    if (!strncasecmp(url, "udp://", 6) || !strncasecmp(url, "rtp://", 6)) {
        if (udp_in_start(ch, url) < 0)
            ch_input_fail(ch, "UDP/RTP bind failed");
        return;
    }
    size_t pl = strcspn(url, "?");
    if ((pl >= 5 && !strncasecmp(url + pl - 5, ".m3u8", 5)) || (pl >= 4 && !strncasecmp(url + pl - 4, ".m3u", 4))) {
        hls_start(ch, url, url, NULL);
        return;
    }
    ch->mode = IN_TS;
    double idle = ch->nurls > 1 ? 12.0 : 20.0;
    ch->tsf = fetch_start(url, ch->ua, &g_ts_cb, ch, ch->nurls > 1 ? 4.5 : 8.0, idle);
    if (!ch->tsf)
        ch_input_fail(ch, "cannot start request");
}

/* ---------------------------------------------------------------- channels */

static void ch_free(void *p)
{
    channel_t *ch = p;
    for (int i = 0; i < ch->nurls; i++)
        free(ch->urls[i]);
    for (int i = 0; i < ch->n_udp_outs; i++) {
        if (ch->udp_outs[i].fd >= 0)
            close(ch->udp_outs[i].fd);
    }
    free(ch->ring);
    buf_free(&ch->cseg);
    buf_free(&ch->probe);
    free(ch);
}

void ch_del(channel_t *ch)
{
    if (!ch)
        return;
    for (channel_t **pp = &g_channels; *pp; pp = &(*pp)->next)
        if (*pp == ch) {
            *pp = ch->next;
            break;
        }
    ch_input_stop(ch);
    while (ch->clients)
        front_close(ch->clients);
    while (ch->waiters) {
        front_t *w = ch->waiters;
        wait_remove(w);
        front_error(w, 404, "Stream stopped");
    }
    hls_out_off(ch);
    bury(ch_free, ch);
}

void ch_wake(channel_t *ch)
{
    ch->last_client_act = g_now;
    if (ch->mode != IN_IDLE)
        return;
    if (!ch->ring) {
        ch->rcap = TS * 22310;
        ch->ring = malloc(ch->rcap);
        if (!ch->ring)
            return;
    }
    ch->wpos = 0;
    memset(ch->out_cc, -1, sizeof ch->out_cc);
    ts_reset_psi(ch);
    ch->win_bytes = 0;
    ch->win_start = g_now;
    ch->bitrate = 0;
    ch->pcr_bitrate = 0;
    ch->next_resize = g_now + 5;
    ch->hls_on = 1;
    ch->cur_started = 0;
    ch->cseg.len = 0;
    ch->fails_row = 0;
    ch->cur = 0;
    ch->last_error[0] = 0;
    ch->idle_reported = 0;
    ch_input_start(ch);
}

static void ch_sleep(channel_t *ch)
{
    if (ch->mode == IN_IDLE)
        return;
    ch_input_stop(ch);
    hls_out_off(ch);
    free(ch->ring);
    ch->ring = NULL;
    ch->rcap = 0;
    ch->wpos = 0;
    ch->bitrate = 0;
    ch->pcr_bitrate = 0;
    ch->win_bytes = 0;
    ch->scr_win = 0;
    ch->scrambled = 0;
    ts_reset_psi(ch);
    ch->mode = IN_IDLE;
    ch->idle_reported = 0;
    snprintf(ch->last_error, sizeof ch->last_error, "idle");
}

channel_t *ch_upsert(const char *id, double seg_dur, int seg_keep, const char *name,
                     char **urls, int nurls, int keep_active, double idle_delay,
                     char **udp_outs, int n_udp_outs)
{
    channel_t *old = ch_find(id);
    if (old)
        ch_del(old);
    if (!urls || nurls <= 0)
        return NULL;
    channel_t *ch = calloc(1, sizeof *ch);
    if (!ch)
        return NULL;
    snprintf(ch->id, sizeof ch->id, "%s", id);
    ch->seg_target = clampd(seg_dur, 1.0, 10.0);
    ch->seg_keep = (int)clampd(seg_keep, 2, 12);
    snprintf(ch->name, sizeof ch->name, "%s", name ? name : "");
    for (int i = 0; i < nurls && ch->nurls < MAX_URLS; i++)
        if (urls[i] && urls[i][0])
            ch->urls[ch->nurls++] = strdup(urls[i]);
    if (!ch->nurls) {
        free(ch);
        return NULL;
    }
    for (int i = 0; i < n_udp_outs && ch->n_udp_outs < MAX_UDP_OUT; i++) {
        int is_rtp = 0, port = 0;
        char lip[64], gip[64];
        if (!udp_outs[i] || parse_udp_spec(udp_outs[i], &is_rtp, lip, sizeof lip, gip, sizeof gip, &port) < 0)
            continue;
        struct in_addr ga;
        if (inet_pton(AF_INET, gip, &ga) != 1)
            continue;
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            continue;
        unsigned char ttl = 32;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
        if (lip[0]) {
            struct in_addr la;
            if (inet_pton(AF_INET, lip, &la) == 1)
                setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &la, sizeof la);
        }
        udp_out_t *uo = &ch->udp_outs[ch->n_udp_outs++];
        uo->fd = fd;
        memset(&uo->addr, 0, sizeof uo->addr);
        uo->addr.sin_family = AF_INET;
        uo->addr.sin_port = htons((uint16_t)port);
        uo->addr.sin_addr = ga;
        uo->n = 0;
    }

    ch->keep_active = keep_active || (ch->n_udp_outs > 0);
    ch->idle_delay = idle_delay >= 5.0 && idle_delay <= 3600.0 ? idle_delay : 20.0;
    for (int i = 0; i < ch->nurls; i++) {
        char *h = strchr(ch->urls[i], '#');
        if (!h)
            continue;
        if (strstr(h + 1, "keep_active"))
            ch->keep_active = 1;
        char *id_opt = strstr(h + 1, "idle_delay=");
        if (id_opt) {
            double d = atof(id_opt + 11);
            if (d >= 5.0 && d <= 3600.0)
                ch->idle_delay = d;
        }
    }
    memset(ch->out_cc, -1, sizeof ch->out_cc);
    ts_reset_psi(ch);
    ch->win_start = g_now;
    ch->next_resize = g_now + 5;
    ch->hls_last_req = -1e9;
    ch->last_client_act = -1e9;
    if (ch->keep_active) {
        ch->rcap = TS * 22310;
        ch->ring = malloc(ch->rcap);
        if (!ch->ring) {
            ch_free(ch);
            return NULL;
        }
        ch->hls_on = 1;
        ch->next = g_channels;
        g_channels = ch;
        ch_input_start(ch);
    } else {
        ch->mode = IN_IDLE;
        ch->hls_on = 0;
        snprintf(ch->last_error, sizeof ch->last_error, "idle");
        ch->next = g_channels;
        g_channels = ch;
    }
    return ch;
}

static void ch_tick(channel_t *ch, int second)
{
    if (ch->mode == IN_IDLE) {
        if (second && !ch->idle_reported) {
            ch->idle_reported = 1;
            ctl_on_ch_idle(ch);
        }
        return;
    }
    if (ch->nclients > 0 || ch->waiters != NULL) {
        ch->last_client_act = g_now;
    } else if (!ch->keep_active) {
        double last_act = fmax(ch->last_client_act, ch->hls_last_req);
        if (g_now - last_act >= ch->idle_delay) {
            ch_sleep(ch);
            if (second && !ch->idle_reported) {
                ch->idle_reported = 1;
                ctl_on_ch_idle(ch);
            }
            return;
        }
    }
    if (ch->mode == IN_WAIT) {
        if (g_now >= ch->retry_at)
            ch_input_start(ch);
    } else {
        double timeout = 10.0;
        if (ch->mode == IN_HLS && ch->hls)
            timeout = fmax(10.0, ch->hls->td * 2.5);
        if (g_now - ch->last_data > timeout) {
            ch->input_errors++;
            ch_input_fail(ch, "no data");
        } else if (ch->mode == IN_HLS && ch->hls) {
            hls_tick(ch->hls);
        }
        if (ch->last_data > ch->in_started && g_now - ch->in_started > 5.0)
            ch->fails_row = 0;
    }
    if (ch->clients && g_now - ch->last_flush >= 0.04) {
        ch->last_flush = g_now;
        for (front_t *c = ch->clients, *nx; c; c = nx) {
            nx = c->cnext;
            if (!c->blocked)
                client_send(c);
            else if (g_now - c->last_progress > 30.0)
                front_close(c);
        }
    }
    for (front_t *w = ch->waiters, *nx; w; w = nx) {
        nx = w->cnext;
        if (ch->nsegs >= 3 || (ch->nsegs >= 1 && g_now > w->wait_until - 1.5)) {
            wait_remove(w);
            send_playlist(w, ch);
        } else if (g_now > w->wait_until) {
            wait_remove(w);
            front_error(w, 503, "HLS segments not yet available");
        }
    }
    if (second) {
        double el = g_now - ch->win_start;
        if (el > 0.2)
            ch->bitrate = (double)ch->win_bytes * 8.0 / el;
        ch->win_bytes = 0;
        ch->win_start = g_now;
        ch->scrambled = ch->scr_win;
        ch->scr_win = 0;
        if (g_now >= ch->next_resize) {
            ch->next_resize = g_now + 5;
            double bps = fmax(ch->bitrate, ch->pcr_bitrate) / 8;
            double secs = fmax(8.0, ch->gop + START_BURST_S + 1.5);
            size_t want = (size_t)clampd(bps * secs, 2.0 * 1024 * 1024, 32.0 * 1024 * 1024);
            if (want > ch->rcap * 1.25 || want < ch->rcap * 0.6)
                ring_resize(ch, want);
        }
    }
}

/* ------------------------------------------------------------- lifecycle */

static void front_sweep(void)
{
    for (front_t *fr = g_fronts, *nx; fr; fr = nx) {
        nx = fr->gnext;
        if (fr->ev.dead)
            continue;
        if ((fr->mode == FR_HEAD || fr->mode == FR_BODY || fr->mode == FR_RESP || fr->mode == FR_WS) &&
            g_now > fr->deadline) {
            front_close(fr);
        }
    }
}

static void on_term(int s)
{
    (void)s;
    g_stop = 1;
}

static void on_hup(int s)
{
    (void)s;
    g_hup = 1;
}

int engine_init(const char *proc_title, int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGHUP, on_hup);

#ifdef __GLIBC__
    mallopt(M_MMAP_THRESHOLD, 128 * 1024);
    mallopt(M_TRIM_THRESHOLD, 1024 * 1024);
    mallopt(M_ARENA_MAX, 2);
#endif

    prctl(PR_SET_NAME, proc_title ? proc_title : "astrag", 0, 0, 0);
    if (argc > 0 && argv && argv[0] && proc_title) {
        char *end = argv[argc - 1] + strlen(argv[argc - 1]);
        size_t span = (size_t)(end - argv[0]);
        if (span >= strlen(proc_title)) {
            memset(argv[0], 0, span);
            memcpy(argv[0], proc_title, strlen(proc_title));
        }
    }

    crc_init();
    g_now = now_s();
    g_ssl = SSL_CTX_new(TLS_client_method());
    if (!g_ssl)
        return -1;
    SSL_CTX_set_verify(g_ssl, SSL_VERIFY_NONE, NULL);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(g_ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_session_cache_mode(g_ssl, SSL_SESS_CACHE_OFF);

    g_ep = epoll_create1(EPOLL_CLOEXEC);
    if (g_ep < 0)
        return -1;

    if (pipe2(g_dpipe, O_CLOEXEC | O_NONBLOCK))
        return -1;
    set_nonblock(g_dpipe[0]);
    int fl = fcntl(g_dpipe[1], F_GETFL);
    fcntl(g_dpipe[1], F_SETFL, fl & ~O_NONBLOCK);
    memset(&g_dev, 0, sizeof g_dev);
    g_dev.type = EV_DNS;
    g_dev.fd = g_dpipe[0];
    ev_watch(&g_dev, EPOLLIN);

    for (int i = 0; i < 3; i++) {
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setstacksize(&a, 256 * 1024);
        pthread_create(&t, &a, dns_thread, NULL);
        pthread_detach(t);
    }
    return 0;
}

void engine_loop(void)
{
    double next_sec = g_now + 1.0, next_trim = g_now + 10.0;
    struct epoll_event evs[256];
    while (!g_stop) {
        int n = epoll_wait(g_ep, evs, 256, 20);
        g_now = now_s();
        if (g_hup) {
            g_hup = 0;
            ctl_on_sighup();
        }
        for (int i = 0; i < n; i++) {
            ev_t *e = evs[i].data.ptr;
            if (!e || e->dead)
                continue;
            uint32_t m = evs[i].events;
            switch (e->type) {
            case EV_LISTEN:
                on_accept(e->obj);
                break;
            case EV_FRONT:
                front_on_event(e->obj, m);
                break;
            case EV_FETCH:
                fetch_on_event(e->obj, m);
                break;
            case EV_DNS:
                dns_on_ready();
                break;
            case EV_UDP_IN:
                udp_in_on_event(e->obj);
                break;
            }
        }
        g_now = now_s();
        int second = g_now >= next_sec;
        if (second)
            next_sec = g_now + 1.0;
        fetch_sweep();
        for (channel_t *ch = g_channels, *nx; ch; ch = nx) {
            nx = ch->next;
            ch_tick(ch, second);
        }
        if (second) {
            ctl_on_tick_1s();
            front_sweep();
        }
        if (second && g_now >= next_trim) {
            next_trim = g_now + 10.0;
#ifdef __GLIBC__
            malloc_trim(0);
#endif
        }
        reap();
    }
}

void engine_cleanup(void)
{
    while (g_channels)
        ch_del(g_channels);
    while (g_fronts)
        front_close(g_fronts);
    while (g_listeners)
        listener_del(g_listeners->port);
    reap();
    buf_free(&g_scr);
    if (g_ssl) {
        SSL_CTX_free(g_ssl);
        g_ssl = NULL;
    }
    if (g_ep >= 0) {
        close(g_ep);
        g_ep = -1;
    }
    if (g_dpipe[0] >= 0)
        close(g_dpipe[0]);
    if (g_dpipe[1] >= 0)
        close(g_dpipe[1]);
}
