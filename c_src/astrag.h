#ifndef ASTRAG_H
#define ASTRAG_H

#include "cjson.h"
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#define ASTRAG_VERSION "AstraG 2.0"
#define ASTRAG_CLI_VERSION "2.0.0"
#define TS 188
#define KF_N 48
#define PCR_HZ 27000000.0
#define PCR_WRAP (8589934592LL * 300LL)
#define MAX_URLS 16
#define MAX_UDP_OUT 8

/* ---- Dynamic buffer ---- */
typedef struct {
    uint8_t *p;
    size_t len, cap;
} buf_t;

int buf_reserve(buf_t *b, size_t n);
int buf_add(buf_t *b, const void *d, size_t n);
int buf_str(buf_t *b, const char *s);
int buf_fmt(buf_t *b, const char *fmt, ...);
void buf_drop(buf_t *b, size_t n);
void buf_free(buf_t *b);

/* ---- Event loop ---- */
enum {
    EV_LISTEN = 1,
    EV_FRONT,
    EV_FETCH,
    EV_DNS,
    EV_UDP_IN,
    EV_SIG
};

typedef struct ev {
    int type, fd, reg, dead;
    uint32_t mask;
    void *obj;
} ev_t;

void ev_watch(ev_t *e, uint32_t mask);
void ev_close(ev_t *e);
void bury(void (*fn)(void *), void *p);

/* ---- DNS & HTTP Client ---- */
typedef struct dnsq dnsq_t;
typedef struct fetch fetch_t;

typedef struct fetch_cb {
    void (*head)(fetch_t *);
    void (*data)(fetch_t *, const uint8_t *, size_t);
    void (*done)(fetch_t *, int ok, const char *err);
} fetch_cb_t;

enum { F_DNS, F_CONN, F_TLS, F_SEND, F_HEAD, F_BODY };

struct fetch {
    ev_t ev;
    SSL *ssl;
    int st;
    char method[16];
    char url[4096], host[256], target[4096], auth[512], ua[256];
    char *extra_hdrs;
    uint8_t *post_body;
    size_t post_len;
    int port, https, redirects;
    double deadline, conn_to, idle_to;
    buf_t req;
    size_t req_off;
    buf_t head;
    int status, chunked, cst, cll;
    int64_t clen, remain;
    char cl[32];
    char ctype[128];
    dnsq_t *dns;
    int paused;
    const char *derr;
    const fetch_cb_t *cb;
    void *owner;
    fetch_t *gnext, *gprev;
};

fetch_t *fetch_start(const char *url, const char *ua, const fetch_cb_t *cb, void *owner,
                     double conn_to, double idle_to);
fetch_t *fetch_start_ex(const char *method, const char *url, const char *ua,
                        const char *extra_hdrs, const void *body, size_t body_len,
                        const fetch_cb_t *cb, void *owner, double conn_to, double idle_to);
void fetch_cancel(fetch_t *f);
void fetch_pause(fetch_t *f, int on);

/* ---- Channel & TS/HLS Engine ---- */
typedef struct front front_t;
typedef struct hls hls_t;
typedef struct channel channel_t;

typedef struct oseg {
    int ref;
    long long seq;
    double dur;
    int disc;
    uint8_t *data;
    size_t len;
} oseg_t;

enum { K_NONE = 0, K_VIDEO = 1, K_AUDIO = 2, K_PMT = 3, K_OTHER = 4 };
enum { IN_WAIT, IN_TS, IN_HLS, IN_IDLE, IN_UDP };

typedef struct psicap {
    int pid;
    uint8_t sec[1024];
    int have, need;
    uint8_t pk[4][TS];
    int npk;
    uint8_t done[4][TS];
    int ndone;
} psicap_t;

typedef struct {
    int fd;
    struct sockaddr_in addr;
    uint8_t pkt[7 * TS];
    int n;
} udp_out_t;

typedef struct {
    ev_t ev;
    channel_t *ch;
    int is_rtp;
} udp_in_t;

struct channel {
    char id[128], name[160];
    char *urls[MAX_URLS];
    int nurls, cur, fails_row;
    double seg_target;
    int seg_keep;
    struct channel *next;
    /* input */
    int mode;
    double retry_at, in_started, last_data, last_good;
    fetch_t *tsf;
    udp_in_t *udpin;
    int ts_checked, probe_m3u;
    buf_t probe;
    hls_t *hls;
    char last_error[256];
    unsigned long long input_errors;
    char ua[256];
    int drop_sdt, drop_eit;
    /* udp outputs */
    udp_out_t udp_outs[MAX_UDP_OUT];
    int n_udp_outs;
    /* TS state */
    uint8_t carry[TS];
    int carry_n, synced;
    int8_t in_cc[8192], out_cc[8192];
    uint8_t kind[8192], stype[8192];
    psicap_t caps[9];
    int ncaps;
    int pmt_pid[8], pnr[8], npmt, tsid;
    int pcr_pid;
    int64_t cur_pcr, br_pcr0;
    uint64_t br_pos0;
    double pcr_bitrate;
    double gop;
    /* ring */
    uint8_t *ring;
    size_t rcap;
    uint64_t wpos;
    uint64_t kf_pos[KF_N];
    int64_t kf_pcr[KF_N];
    double kf_wall[KF_N];
    int kf_head, kf_cnt;
    double next_resize;
    /* TS viewers / HLS waiters */
    front_t *clients;
    int nclients;
    front_t *waiters;
    double last_flush;
    /* HLS out (astron double-buffered segments) */
    int hls_on, cur_started, cur_disc, disc_pending;
    double hls_last_req, cur_t0_wall;
    int64_t cur_t0_pcr;
    oseg_t *segs[16];
    int nsegs;
    long long next_seq;
    buf_t cseg;
    /* stats */
    uint64_t win_bytes, packets, cc_err, pes_err, sync_losses;
    double win_start, bitrate;
    int scr_win, scrambled;
    uint64_t prev_cc_stat, prev_pes_stat;
    int was_active_ws;
    /* on-demand & cluster metadata */
    int keep_active, idle_reported;
    double idle_delay, last_client_act;
    int is_cluster;
    char cluster_host[128];
    char cluster_orig_id[128];
};

/* ---- Front HTTP/WS Client ---- */
enum { FR_HEAD, FR_BODY, FR_CFETCH, FR_WS, FR_TS, FR_RESP, FR_WAIT };

struct front {
    ev_t ev;
    int mode;
    int listen_port;
    char ip[64];
    buf_t in, out;
    size_t out_off;
    size_t head_len;
    int64_t body_need;
    oseg_t *seg;
    size_t seg_off;
    fetch_t *cfetch; /* async cluster HTTP fetch */
    int close_when_done, blocked;
    double deadline;
    char ua[200], login[96];
    channel_t *ch;
    uint64_t pos;
    buf_t pre;
    size_t pre_off;
    int wait_kf;
    double kf_deadline;
    double last_progress;
    unsigned long long sess;
    time_t sess_start_wall;
    int64_t sess_sdate_ms;
    char hls_pre[700], hls_suf[700];
    int head_only;
    double wait_until;
    /* WebSocket state (FR_WS) */
    int ws_is_cluster;
    int ws_authed;
    int ws_admin;
    char ws_login[96];
    char ws_cluster_host[128];
    uint8_t ws_frag_op;
    buf_t ws_frag;
    front_t *cnext, *cprev;
    front_t *gnext, *gprev;
};

/* ---- Engine Globals & API ---- */
extern double g_now;
extern int g_ep;
extern channel_t *g_channels;
extern front_t *g_fronts;
extern volatile sig_atomic_t g_stop;

int engine_init(const char *proc_title, int argc, char **argv);
void engine_loop(void);
void engine_cleanup(void);

int listener_add(const char *host, int port);
void listener_del(int port);
int listener_has(int port);

channel_t *ch_find(const char *id);
channel_t *ch_upsert(const char *id, double seg_dur, int seg_keep, const char *name,
                     char **urls, int nurls, int keep_active, double idle_delay,
                     char **udp_outs, int n_udp_outs);
void ch_del(channel_t *ch);
void ch_wake(channel_t *ch);
void ch_serve_ts(front_t *fr, channel_t *ch, const char *login);
void ch_serve_hls(front_t *fr, channel_t *ch, const char *pre, const char *suf, int head_only);
void ch_serve_seg(front_t *fr, channel_t *ch, const char *seg_name, int head_only);

void front_close(front_t *fr);
void front_flush(front_t *fr);
void front_respond(front_t *fr, int code, const char *reason, const char *ctype,
                   const char *extra, const void *body, size_t blen, oseg_t *seg, int head_only);
void front_respond_status_raw(front_t *fr, int code, const char *reason,
                              const char *headers, const void *body, size_t blen);
void front_error(front_t *fr, int code, const char *reason);

void ws_upgrade(front_t *fr, const char *accept_b64, int is_cluster, const char *cluster_host);
void ws_send_text(front_t *fr, const char *txt, size_t len);
void ws_send_close(front_t *fr, uint16_t code);

/* ---- Hooks implemented by astrag_ctl.c ---- */
void ctl_http_handle(front_t *fr, size_t head_len, size_t body_len);
void ctl_ws_on_message(front_t *fr, const char *msg, size_t len);
void ctl_ws_on_close(front_t *fr);
void ctl_on_sess_add(front_t *fr, channel_t *ch);
void ctl_on_sess_del(front_t *fr);
void ctl_on_tick_1s(void);
void ctl_on_ch_idle(channel_t *ch);
void ctl_on_sighup(void);

/* ---- Control & CLI entry points ---- */
int ctl_init(const char *config_path, const char *cli_host, int cli_port);
void ctl_cleanup(void);
int ctl_verify_password(const char *pw, const char *stored);
int ctl_atomic_write_file(const char *path, const char *data, size_t len, unsigned int mode);
int ctl_read_file_str(const char *path, char **out, size_t *out_len);

#endif
