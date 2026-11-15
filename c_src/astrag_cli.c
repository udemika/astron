#define _GNU_SOURCE
#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0

#include "astrag.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int is_digits(const char *s)
{
    if (!s || !*s)
        return 0;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s))
            return 0;
    }
    return 1;
}

static int run_argv(char *const argv[], int quiet, char *out_buf, size_t out_sz)
{
    int pfd[2] = {-1, -1};
    if (out_buf && out_sz > 0) {
        out_buf[0] = 0;
        if (pipe(pfd) < 0)
            pfd[0] = pfd[1] = -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (pfd[0] >= 0) {
            close(pfd[0]);
            close(pfd[1]);
        }
        return -1;
    }
    if (pid == 0) {
        if (pfd[1] >= 0) {
            close(pfd[0]);
            dup2(pfd[1], STDOUT_FILENO);
            if (quiet) {
                int dn = open("/dev/null", O_WRONLY);
                if (dn >= 0) {
                    dup2(dn, STDERR_FILENO);
                    close(dn);
                }
            } else {
                dup2(pfd[1], STDERR_FILENO);
            }
            close(pfd[1]);
        } else if (quiet) {
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) {
                dup2(dn, STDOUT_FILENO);
                dup2(dn, STDERR_FILENO);
                close(dn);
            }
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pfd[1] >= 0)
        close(pfd[1]);
    if (pfd[0] >= 0) {
        size_t pos = 0;
        while (pos + 1 < out_sz) {
            ssize_t r = read(pfd[0], out_buf + pos, out_sz - 1 - pos);
            if (r <= 0)
                break;
            pos += (size_t)r;
        }
        out_buf[pos] = 0;
        close(pfd[0]);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static void chown_path(const char *path, uid_t uid, gid_t gid)
{
    if (chown(path, uid, gid) != 0) {
        /* ignore if running unprivileged */
    }
}

static int install_self_binary(const char *dst_path)
{
    char self_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n <= 0)
        return -1;
    self_path[n] = 0;

    struct stat st_src, st_dst;
    if (stat(self_path, &st_src) < 0)
        return -1;
    if (stat(dst_path, &st_dst) == 0 && st_src.st_dev == st_dst.st_dev && st_src.st_ino == st_dst.st_ino) {
        chmod(dst_path, 0755);
        return 0;
    }

    int in_fd = open(self_path, O_RDONLY);
    if (in_fd < 0)
        return -1;

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s.tmp.XXXXXX", dst_path);
    int out_fd = mkstemp(tmp);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    uint8_t buf[65536];
    for (;;) {
        ssize_t r = read(in_fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            close(in_fd);
            close(out_fd);
            unlink(tmp);
            return -1;
        }
        if (r == 0)
            break;
        size_t off = 0;
        while (off < (size_t)r) {
            ssize_t w = write(out_fd, buf + off, (size_t)r - off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                close(in_fd);
                close(out_fd);
                unlink(tmp);
                return -1;
            }
            off += (size_t)w;
        }
    }
    fsync(out_fd);
    fchmod(out_fd, 0755);
    fchown(out_fd, 0, 0);
    close(in_fd);
    close(out_fd);

    if (rename(tmp, dst_path) < 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static jval_t *build_default_init_cfg(int port)
{
    jval_t *cfg = j_obj();
    j_set(cfg, "port", j_int(port));
    j_set(cfg, "host", j_str("0.0.0.0"));
    j_set(cfg, "gid", j_int(466560));
    jval_t *auth = j_obj();
    j_set(auth, "enable", j_bool(0));
    j_set(cfg, "auth", auth);
    jval_t *users = j_obj();
    jval_t *adm = j_obj();
    j_set(adm, "type", j_int(1));
    j_set(adm, "role", j_str("admin"));
    j_set(adm, "enable", j_bool(1));
    j_set(adm, "password", j_str("admin"));
    j_set(adm, "created", j_int((int64_t)time(NULL)));
    j_set(users, "admin", adm);
    j_set(cfg, "users", users);
    j_set(cfg, "make_stream", j_arr());
    j_set(cfg, "categories", j_arr());
    j_set(cfg, "servers", j_arr());
    j_set(cfg, "softcam", j_arr());
    j_set(cfg, "cas", j_arr());
    j_set(cfg, "dvb_tune", j_arr());
    j_set(cfg, "settings", j_obj());
    j_set(cfg, "hls", j_obj());
    return cfg;
}

static jval_t *load_json_obj_or_cfg(const char *path)
{
    char *raw = NULL;
    if (ctl_read_file_str(path, &raw, NULL) < 0)
        return NULL;
    char *p = raw;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '{') {
        free(raw);
        return NULL;
    }
    jval_t *v = j_parse(p);
    free(raw);
    if (!j_is_obj(v)) {
        j_free(v);
        return NULL;
    }
    const jval_t *sub = j_get(v, "config");
    if (j_is_obj(sub)) {
        jval_t *dup = j_dup(sub);
        j_free(v);
        return dup;
    }
    return v;
}

static jval_t *order_init_cfg(const jval_t *src, int port)
{
    static const char *keys[] = {
        "port", "host", "gid", "auth", "users", "make_stream",
        "categories", "servers", "softcam", "cas", "dvb_tune", "settings", "hls"
    };
    jval_t *ord = build_default_init_cfg(port);
    if (src) {
        for (jval_t *c = src->child; c; c = c->next) {
            if (!c->key || !strcmp(c->key, "control_port"))
                continue;
            j_set(ord, c->key, j_dup(c));
        }
        j_set(ord, "port", j_int(port));
        if (!j_get_str(ord, "host", NULL) || !*j_get_str(ord, "host", ""))
            j_set(ord, "host", j_str("0.0.0.0"));
        jval_t *users = j_get(ord, "users");
        if (j_is_obj(users)) {
            for (jval_t *u = users->child; u; u = u->next) {
                const char *pw = j_get_str(u, "password", "");
                if (!strncmp(pw, "pbkdf2_sha256$", 14) && ctl_verify_password("admin", pw))
                    j_set(u, "password", j_str("admin"));
            }
        }
        jval_t *au = j_get(ord, "auth");
        if (j_is_obj(au) && j_get_bool(au, "enable", 0) &&
            !j_get(au, "backend") && !j_get(au, "iptvportal") &&
            !j_get(au, "ministra") && !j_get(au, "smarty") &&
            !j_get(au, "http_ip_allow") && !j_get(au, "http_ip_deny") &&
            !j_get(au, "http_token_deny") && !j_get(au, "securetoken") &&
            !j_get(au, "promo")) {
            int has_user_tok = 0;
            if (j_is_obj(users)) {
                for (const jval_t *u = users->child; u; u = u->next) {
                    const char *ut = j_get_str(u, "token", "");
                    if (*ut) { has_user_tok = 1; break; }
                }
            }
            if (!has_user_tok)
                j_set(au, "enable", j_bool(0));
        }
    }
    jval_t *final_ord = j_obj();
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        const jval_t *v = j_get(ord, keys[i]);
        if (v)
            j_set(final_ord, keys[i], j_dup(v));
    }
    for (jval_t *c = ord->child; c; c = c->next) {
        if (c->key && !j_get(final_ord, c->key))
            j_set(final_ord, c->key, j_dup(c));
    }
    j_free(ord);
    return final_ord;
}

static int save_json_pretty(const char *path, const jval_t *cfg, mode_t mode)
{
    char *txt = j_print(cfg, 1);
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
    int r = ctl_atomic_write_file(path, out, tl + 1, (unsigned int)mode);
    free(out);
    return r;
}

static void detect_server_ip(char *out, size_t outsz)
{
    snprintf(out, outsz, "127.0.0.1");
    char *argv[] = {"hostname", "-I", NULL};
    char buf[256];
    if (run_argv(argv, 1, buf, sizeof buf) == 0 && buf[0]) {
        char *p = buf;
        while (*p && isspace((unsigned char)*p))
            p++;
        size_t n = 0;
        while (p[n] && !isspace((unsigned char)p[n]))
            n++;
        if (n > 0 && n < outsz) {
            memcpy(out, p, n);
            out[n] = 0;
        }
    }
}

static int ensure_astrag_user(uid_t *uid_out, gid_t *gid_out)
{
    if (!getgrnam("astrag")) {
        char *argv[] = {"groupadd", "--system", "astrag", NULL};
        run_argv(argv, 1, NULL, 0);
    }
    if (!getpwnam("astrag")) {
        char *argv[] = {
            "useradd", "--system", "--gid", "astrag",
            "--home-dir", "/var/lib/astrag", "--no-create-home",
            "--shell", "/usr/sbin/nologin", "astrag", NULL
        };
        run_argv(argv, 1, NULL, 0);
    }
    struct passwd *pw = getpwnam("astrag");
    if (!pw || pw->pw_uid == 0) {
        fprintf(stderr, "[AstraG] Ошибка: не удалось создать системного пользователя 'astrag'.\n");
        return -1;
    }
    *uid_out = pw->pw_uid;
    *gid_out = pw->pw_gid;
    return 0;
}

static int cmd_init(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr, "[AstraG] Ошибка: выполните установку от имени root (sudo astrag init ...)\n");
        return 1;
    }

    int port = 8000;
    const char *custom_name = NULL;
    int start_now = 0;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if ((!strcmp(a, "-p") || !strcmp(a, "--port")) && i + 1 < argc) {
            int p = atoi(argv[++i]);
            if (p < 1 || p > 65535) {
                fprintf(stderr, "[AstraG] Ошибка: некорректный порт.\n");
                return 2;
            }
            port = p;
        } else if (!strcmp(a, "--start") || !strcmp(a, "--now")) {
            start_now = 1;
        } else if (!strcmp(a, "--no-start")) {
            start_now = 0;
        } else if (!strcmp(a, "--binary") || !strcmp(a, "--bin") || !strcmp(a, "--single-binary") ||
                   !strcmp(a, "--apt") || !strcmp(a, "--system")) {
            /* Single native C binary already contains everything; kept for CLI compatibility */
        } else if (a[0] != '-') {
            if (is_digits(a)) {
                int p = atoi(a);
                if (p < 1 || p > 65535) {
                    fprintf(stderr, "[AstraG] Ошибка: порт должен быть от 1 до 65535.\n");
                    return 2;
                }
                port = p;
            } else if (!custom_name) {
                custom_name = a;
            }
        }
    }

    char service_name[128];
    if (custom_name && *custom_name) {
        snprintf(service_name, sizeof service_name, "%s", custom_name);
        size_t sl = strlen(service_name);
        if (sl > 8 && !strcmp(service_name + sl - 8, ".service"))
            service_name[sl - 8] = 0;
    } else if (port == 8000) {
        snprintf(service_name, sizeof service_name, "astrag");
    } else {
        snprintf(service_name, sizeof service_name, "astrag%d", port);
    }

    char unit_name[160];
    snprintf(unit_name, sizeof unit_name, "%s.service", service_name);

    /* Stop old Python service if running before replacing /usr/bin/astrag */
    char *was_active_argv[] = {"systemctl", "is-active", "--quiet", unit_name, NULL};
    int was_active = (run_argv(was_active_argv, 1, NULL, 0) == 0);

    uid_t uid = 0;
    gid_t gid = 0;
    if (ensure_astrag_user(&uid, &gid) < 0)
        return 1;

    mkdir_p("/etc/astrag", 0750);
    chown_path("/etc/astrag", uid, gid);
    chmod("/etc/astrag", 0750);

    mkdir_p("/var/lib/astrag", 0750);
    chown_path("/var/lib/astrag", uid, gid);
    chmod("/var/lib/astrag", 0750);

    if (install_self_binary("/usr/bin/astrag") < 0) {
        fprintf(stderr, "[AstraG] Ошибка: не удалось установить бинарник в /usr/bin/astrag (%s)\n",
                strerror(errno));
        return 1;
    }
    unlink("/usr/local/bin/astrag");
    unlink("/usr/local/bin/astra-clone");
    unlink("/usr/bin/astra-clone");
    if (symlink("/usr/bin/astrag", "/usr/bin/astra-clone") != 0) {
        /* ignore non-fatal symlink error */
    }

    /* Legacy astra-clone state migration if needed */
    struct stat st_dummy;
    if (stat("/var/lib/astrag/state.json", &st_dummy) != 0 &&
        stat("/var/lib/astra-clone/state.json", &st_dummy) == 0) {
        char *raw = NULL;
        size_t rlen = 0;
        if (ctl_read_file_str("/var/lib/astra-clone/state.json", &raw, &rlen) == 0) {
            ctl_atomic_write_file("/var/lib/astrag/state.json", raw, rlen, 0640);
            chown_path("/var/lib/astrag/state.json", uid, gid);
            free(raw);
        }
    }
    char *ac_stop[] = {"systemctl", "stop", "astra-clone.service", NULL};
    char *ac_dis[] = {"systemctl", "disable", "astra-clone.service", NULL};
    run_argv(ac_stop, 1, NULL, 0);
    run_argv(ac_dis, 1, NULL, 0);

    char conf_path[512];
    snprintf(conf_path, sizeof conf_path, "/etc/astrag/%s.conf", service_name);

    jval_t *existing = load_json_obj_or_cfg(conf_path);
    if (!existing && !strcmp(service_name, "astrag"))
        existing = load_json_obj_or_cfg("/var/lib/astrag/state.json");
    jval_t *final_cfg = order_init_cfg(existing, port);
    j_free(existing);

    if (save_json_pretty(conf_path, final_cfg, 0640) < 0) {
        j_free(final_cfg);
        fprintf(stderr, "[AstraG] Ошибка записи %s: %s\n", conf_path, strerror(errno));
        return 1;
    }
    j_free(final_cfg);
    chown_path(conf_path, uid, gid);
    chmod(conf_path, 0640);

    char unit_path[512];
    snprintf(unit_path, sizeof unit_path, "/etc/systemd/system/%s", unit_name);
    char unit_buf[2048];
    int ulen = snprintf(unit_buf, sizeof unit_buf,
        "[Unit]\n"
        "Description=AstraG Control Panel and IPTV Streaming Server (%s)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=astrag\n"
        "Group=astrag\n"
        "WorkingDirectory=/var/lib/astrag\n"
        "Environment=\"MALLOC_MMAP_THRESHOLD_=1048576\"\n"
        "Environment=\"MALLOC_TRIM_THRESHOLD_=131072\"\n"
        "Environment=\"MALLOC_ARENA_MAX=2\"\n"
        "Environment=\"ASTRA_CONFIG_FILE=%s\"\n"
        "ExecStart=/usr/bin/astrag -c %s\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=always\n"
        "RestartSec=3\n"
        "StateDirectory=astrag\n"
        "StateDirectoryMode=0750\n"
        "ConfigurationDirectory=astrag\n"
        "ConfigurationDirectoryMode=0750\n"
        "UMask=0027\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "ReadWritePaths=/etc/astrag /var/lib/astrag\n"
        "LimitNOFILE=65536\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        service_name, conf_path, conf_path);

    if (ctl_atomic_write_file(unit_path, unit_buf, (size_t)ulen, 0644) < 0) {
        fprintf(stderr, "[AstraG] Ошибка записи %s\n", unit_path);
        return 1;
    }
    chown_path(unit_path, 0, 0);
    chmod(unit_path, 0644);

    /* Open firewall port if UFW is active */
    char ufw_out[256];
    char *ufw_st[] = {"ufw", "status", NULL};
    if (run_argv(ufw_st, 1, ufw_out, sizeof ufw_out) == 0 && strstr(ufw_out, "Status: active")) {
        char port_rule[32];
        snprintf(port_rule, sizeof port_rule, "%d/tcp", port);
        char *ufw_allow[] = {"ufw", "allow", port_rule, NULL};
        run_argv(ufw_allow, 1, NULL, 0);
    }

    char *reload_argv[] = {"systemctl", "daemon-reload", NULL};
    run_argv(reload_argv, 1, NULL, 0);

    /* Also restart any other active astrag*.service instances so they pick up the updated /usr/bin/astrag binary */
    DIR *sdir = opendir("/etc/systemd/system");
    if (sdir) {
        struct dirent *de;
        while ((de = readdir(sdir)) != NULL) {
            size_t nl = strlen(de->d_name);
            if (nl > 8 && !strncmp(de->d_name, "astrag", 6) &&
                !strcmp(de->d_name + nl - 8, ".service") &&
                strcmp(de->d_name, unit_name) != 0) {
                char *chk_argv[] = {"systemctl", "is-active", "--quiet", de->d_name, NULL};
                if (run_argv(chk_argv, 1, NULL, 0) == 0) {
                    char *rst_argv[] = {"systemctl", "restart", de->d_name, NULL};
                    run_argv(rst_argv, 1, NULL, 0);
                }
            }
        }
        closedir(sdir);
    }

    printf("[AstraG] Нативный бинарник установлен: /usr/bin/astrag\n");
    printf("[AstraG] Конфигурация сохранена:     %s\n", conf_path);
    printf("[AstraG] Сервис systemd зарегистрирован: %s\n", unit_path);

    if (start_now || was_active) {
        char *en_argv[] = {"systemctl", "enable", unit_name, NULL};
        char *rs_argv[] = {"systemctl", "restart", unit_name, NULL};
        run_argv(en_argv, 1, NULL, 0);
        run_argv(rs_argv, 0, NULL, 0);
        sleep(1);
        if (run_argv(was_active_argv, 1, NULL, 0) != 0) {
            fprintf(stderr, "[AstraG] Ошибка запуска %s. Последние логи:\n", unit_name);
            char *j_argv[] = {"journalctl", "-u", unit_name, "-n", "30", "--no-pager", NULL};
            run_argv(j_argv, 0, NULL, 0);
            return 1;
        }
        char ip[128];
        detect_server_ip(ip, sizeof ip);
        printf("================================================================\n");
        printf(" AstraG (%s) запущен!\n", service_name);
        printf(" Конфиг            : %s\n", conf_path);
        printf(" Веб-панель        : http://%s:%d/\n", ip, port);
        printf(" Логин / Пароль    : admin / admin\n");
        printf(" Плейлист M3U8     : http://%s:%d/playlist.m3u8\n", ip, port);
        printf("================================================================\n");
    } else {
        printf("\nТеперь выполните:\n");
        printf("  systemctl start %s\n", service_name);
        printf("  systemctl enable %s\n", service_name);
    }
    return 0;
}

static void rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return;
    if (!S_ISDIR(st.st_mode)) {
        unlink(path);
        return;
    }
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            char sub[PATH_MAX];
            snprintf(sub, sizeof sub, "%s/%s", path, de->d_name);
            rm_rf(sub);
        }
        closedir(d);
    }
    rmdir(path);
}

static int cmd_remove(int argc, char **argv, int force_purge)
{
    if (geteuid() != 0) {
        fprintf(stderr, "[AstraG] Ошибка: выполните от имени root (sudo astrag remove ...)\n");
        return 1;
    }
    const char *target = NULL;
    int purge = force_purge;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--purge") || !strcmp(argv[i], "-P") || !strcmp(argv[i], "purge"))
            purge = 1;
        else if (argv[i][0] != '-' && !target)
            target = argv[i];
    }

    char service_name[128];
    if (!target)
        snprintf(service_name, sizeof service_name, "astrag");
    else if (is_digits(target)) {
        int p = atoi(target);
        if (p == 8000)
            snprintf(service_name, sizeof service_name, "astrag");
        else
            snprintf(service_name, sizeof service_name, "astrag%d", p);
    } else {
        snprintf(service_name, sizeof service_name, "%s", target);
        size_t sl = strlen(service_name);
        if (sl > 8 && !strcmp(service_name + sl - 8, ".service"))
            service_name[sl - 8] = 0;
    }

    char unit_name[160], unit_path[512];
    snprintf(unit_name, sizeof unit_name, "%s.service", service_name);
    snprintf(unit_path, sizeof unit_path, "/etc/systemd/system/%s", unit_name);

    char *st_argv[] = {"systemctl", "stop", unit_name, NULL};
    char *di_argv[] = {"systemctl", "disable", unit_name, NULL};
    run_argv(st_argv, 1, NULL, 0);
    run_argv(di_argv, 1, NULL, 0);
    unlink(unit_path);

    char *dr_argv[] = {"systemctl", "daemon-reload", NULL};
    char *rf_argv[] = {"systemctl", "reset-failed", NULL};
    run_argv(dr_argv, 1, NULL, 0);
    run_argv(rf_argv, 1, NULL, 0);
    printf("[AstraG] Сервис '%s' остановлен и удален из systemd.\n", service_name);

    if (purge) {
        if (target && strcmp(service_name, "astrag") != 0) {
            char cp[512];
            snprintf(cp, sizeof cp, "/etc/astrag/%s.conf", service_name);
            unlink(cp);
            printf("[AstraG] Конфигурационный файл %s удален.\n", cp);
        } else {
            DIR *d = opendir("/etc/systemd/system");
            if (d) {
                struct dirent *de;
                while ((de = readdir(d)) != NULL) {
                    size_t nl = strlen(de->d_name);
                    if (nl > 8 && !strcmp(de->d_name + nl - 8, ".service") &&
                        (!strncmp(de->d_name, "astrag", 6) || !strcmp(de->d_name, "astra-clone.service"))) {
                        char *s2[] = {"systemctl", "stop", de->d_name, NULL};
                        char *d2[] = {"systemctl", "disable", de->d_name, NULL};
                        run_argv(s2, 1, NULL, 0);
                        run_argv(d2, 1, NULL, 0);
                        char fp[512];
                        snprintf(fp, sizeof fp, "/etc/systemd/system/%s", de->d_name);
                        unlink(fp);
                    }
                }
                closedir(d);
            }
            run_argv(dr_argv, 1, NULL, 0);
            rm_rf("/opt/astrag");
            rm_rf("/opt/astra-clone");
            rm_rf("/etc/astrag");
            rm_rf("/etc/astra-clone");
            rm_rf("/var/lib/astrag");
            rm_rf("/var/lib/astra-clone");
            rm_rf("/var/log/astrag");
            char *ud[] = {"userdel", "astrag", NULL};
            char *gd[] = {"groupdel", "astrag", NULL};
            run_argv(ud, 1, NULL, 0);
            run_argv(gd, 1, NULL, 0);
            unlink("/usr/bin/astra-clone");
            unlink("/usr/bin/astrag");
            printf("[AstraG] Все файлы (/etc/astrag, /var/lib/astrag, /opt/astrag, /usr/bin/astrag) полностью удалены.\n");
        }
    }
    return 0;
}

static int cmd_reset_password(int argc, char **argv)
{
    const char *conf = getenv("ASTRA_CONFIG_FILE");
    char conf_buf[1024];
    snprintf(conf_buf, sizeof conf_buf, "%s", (conf && *conf) ? conf : "/etc/astrag/astrag.conf");
    const char *pos[4] = {NULL};
    int npos = 0;

    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc) {
            snprintf(conf_buf, sizeof conf_buf, "%s", argv[++i]);
        } else if (argv[i][0] != '-' && npos < 4) {
            pos[npos++] = argv[i];
        }
    }
    const char *login = npos >= 1 ? pos[0] : "admin";
    const char *password = npos >= 2 ? pos[1] : "admin";

    jval_t *cfg = load_json_obj_or_cfg(conf_buf);
    if (!cfg)
        cfg = build_default_init_cfg(8000);
    int port = (int)j_get_int(cfg, "port", 8000);
    if (port <= 0)
        port = 8000;

    jval_t *auth = j_get(cfg, "auth");
    if (!j_is_obj(auth)) {
        auth = j_obj();
        j_set(auth, "enable", j_bool(0));
        j_set(cfg, "auth", auth);
    }

    jval_t *users = j_get(cfg, "users");
    if (!j_is_obj(users)) {
        users = j_obj();
        j_set(cfg, "users", users);
    }
    jval_t *u = j_obj();
    j_set(u, "type", j_int(1));
    j_set(u, "role", j_str("admin"));
    j_set(u, "enable", j_bool(1));
    j_set(u, "password", j_str(password));
    j_set(u, "created", j_int((int64_t)time(NULL)));
    j_set(users, login, u);

    jval_t *ord = order_init_cfg(cfg, port);
    j_free(cfg);
    if (save_json_pretty(conf_buf, ord, 0640) < 0) {
        j_free(ord);
        fprintf(stderr, "[AstraG] Ошибка записи %s: %s\n", conf_buf, strerror(errno));
        return 1;
    }
    j_free(ord);
    struct passwd *pw = getpwnam("astrag");
    if (pw && geteuid() == 0)
        chown_path(conf_buf, pw->pw_uid, pw->pw_gid);
    chmod(conf_buf, 0640);
    printf("[AstraG] Учетная запись '%s' (пароль '%s') сохранена в %s.\n", login, password, conf_buf);
    return 0;
}

static void print_help(void)
{
    printf(
        "AstraG v%s — Native Single-Binary MPEG-TS / HLS Broadcast Server\n\n"
        "Использование:\n"
        "  astrag init [port] [name] [--start]    Создать конфиг /etc/astrag/astrag[port].conf и сервис systemd\n"
        "  astrag remove [port|name] [--purge]    Удалить сервис systemd (с --purge удаляет конфиги и файлы)\n"
        "  astrag -c <config> [-p <port>]         Запустить сервер вещания и веб-панель напрямую\n"
        "  astrag reset-password [user] [pass]    Сбросить логин и пароль в /etc/astrag/astrag.conf\n"
        "  astrag -v, --version                   Показать версию AstraG\n"
        "  astrag -h, --help                      Показать эту справку\n",
        ASTRAG_CLI_VERSION);
}

int main(int argc, char **argv)
{
    if (argc >= 2) {
        const char *cmd = argv[1];
        if (!strcmp(cmd, "-v") || !strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
            printf("AstraG %s\n", ASTRAG_CLI_VERSION);
            return 0;
        }
        if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
            print_help();
            return 0;
        }
        if (!strcmp(cmd, "init"))
            return cmd_init(argc - 2, argv + 2);
        if (!strcmp(cmd, "remove") || !strcmp(cmd, "uninstall"))
            return cmd_remove(argc - 2, argv + 2, 0);
        if (!strcmp(cmd, "purge"))
            return cmd_remove(argc - 2, argv + 2, 1);
        if (!strcmp(cmd, "reset-password"))
            return cmd_reset_password(argc - 2, argv + 2);
    }

    char conf_buf[1024] = "";
    char host_buf[64] = "";
    char pid_buf[1024] = "";
    int port = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((!strcmp(a, "-c") || !strcmp(a, "--config")) && i + 1 < argc) {
            snprintf(conf_buf, sizeof conf_buf, "%s", argv[++i]);
        } else if ((!strcmp(a, "-p") || !strcmp(a, "--port")) && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (!strcmp(a, "--host") && i + 1 < argc) {
            snprintf(host_buf, sizeof host_buf, "%s", argv[++i]);
        } else if (!strcmp(a, "--pid") && i + 1 < argc) {
            snprintf(pid_buf, sizeof pid_buf, "%s", argv[++i]);
        } else if (a[0] != '-' && !conf_buf[0] && strlen(a) > 5 &&
                   (!strcmp(a + strlen(a) - 5, ".conf") || !strcmp(a + strlen(a) - 5, ".json"))) {
            snprintf(conf_buf, sizeof conf_buf, "%s", a);
        }
    }

    if (pid_buf[0]) {
        char pbuf[32];
        int pn = snprintf(pbuf, sizeof pbuf, "%d\n", (int)getpid());
        ctl_atomic_write_file(pid_buf, pbuf, (size_t)pn, 0644);
    }

    if (engine_init("astrag", argc, argv) < 0)
        return 1;
    if (ctl_init(conf_buf[0] ? conf_buf : NULL, host_buf[0] ? host_buf : NULL, port) < 0) {
        engine_cleanup();
        return 1;
    }

    engine_loop();

    ctl_cleanup();
    engine_cleanup();
    if (pid_buf[0])
        unlink(pid_buf);
    return 0;
}
