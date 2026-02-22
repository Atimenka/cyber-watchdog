/*
 * CYBER-WATCHDOG v2.2 — Kernel & Driver Health Monitor
 * Clean rewrite. ncurses TUI + Console + Daemon.
 *
 * ncurses defines macros ERR, OK — so our enum uses S_ prefix.
 * Every statement on its own line — no misleading indentation.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <optional>
#include <numeric>
#include <iomanip>
#include <regex>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <csignal>
#include <ctime>
#include <cstdint>
#include <climits>

#include <unistd.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>

#include <curl/curl.h>
#include <ncurses.h>

using SteadyClock = std::chrono::steady_clock;
using namespace std::chrono_literals;

/* ── Severity: names that NEVER clash with ncurses macros ── */
enum {
    S_DEBUG   = 0,
    S_INFO    = 1,
    S_NOTICE  = 2,
    S_WARNING = 3,
    S_ERROR   = 4,
    S_CRIT    = 5,
    S_EMERG   = 6
};

static const char* sev_tag(int s) {
    switch (s) {
        case S_DEBUG:   return "DBG";
        case S_INFO:    return "INF";
        case S_NOTICE:  return "NOT";
        case S_WARNING: return "WRN";
        case S_ERROR:   return "ERR";
        case S_CRIT:    return "CRT";
        case S_EMERG:   return "EMG";
        default:        return "???";
    }
}

/* ── ncurses color pair IDs ── */
enum {
    CP_GREEN = 1, CP_YELLOW, CP_RED, CP_CYAN, CP_MAGENTA,
    CP_DIM, CP_HEADER, CP_ALERT, CP_BAR_LO, CP_BAR_MD,
    CP_BAR_HI, CP_TAB_ON, CP_TAB_OFF, CP_BORDER
};

static void setup_colors() {
    start_color();
    use_default_colors();
    init_pair(CP_GREEN,   COLOR_GREEN,   -1);
    init_pair(CP_YELLOW,  COLOR_YELLOW,  -1);
    init_pair(CP_RED,     COLOR_RED,     -1);
    init_pair(CP_CYAN,    COLOR_CYAN,    -1);
    init_pair(CP_MAGENTA, COLOR_MAGENTA, -1);
    init_pair(CP_DIM,     COLOR_WHITE,   -1);
    init_pair(CP_HEADER,  COLOR_BLACK,   COLOR_GREEN);
    init_pair(CP_ALERT,   COLOR_WHITE,   COLOR_RED);
    init_pair(CP_BAR_LO,  COLOR_GREEN,   -1);
    init_pair(CP_BAR_MD,  COLOR_YELLOW,  -1);
    init_pair(CP_BAR_HI,  COLOR_RED,     -1);
    init_pair(CP_TAB_ON,  COLOR_BLACK,   COLOR_GREEN);
    init_pair(CP_TAB_OFF, COLOR_GREEN,   -1);
    init_pair(CP_BORDER,  COLOR_GREEN,   -1);
}

static int sev_cp(int s) {
    if (s >= S_CRIT) {
        return CP_RED;
    }
    if (s >= S_WARNING) {
        return CP_YELLOW;
    }
    return CP_DIM;
}

/* ── Filesystem helpers ── */
namespace FS {
    static bool exists(const std::string& p) {
        struct stat st;
        return stat(p.c_str(), &st) == 0;
    }
    static bool isdir(const std::string& p) {
        struct stat st;
        return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    }
    static void mkdirs(const std::string& p) {
        std::string cmd = "mkdir -p '" + p + "' 2>/dev/null";
        (void)system(cmd.c_str());
    }
}

/* ── Config ── */
namespace Cfg {
    constexpr const char* VER      = "2.2.0";
    constexpr const char* BIN      = "/usr/local/sbin/cyber-watchdog";
    constexpr const char* LOGDIR   = "/var/log/cyber-watchdog";
    constexpr const char* LOGFILE  = "/var/log/cyber-watchdog/watchdog.log";
    constexpr const char* PIDFILE  = "/var/run/cyber-watchdog.pid";
    constexpr const char* CONFFILE = "/etc/cyber-watchdog.conf";
    constexpr const char* API_URL  = "https://openrouter.ai/api/v1/chat/completions";
    constexpr const char* MODEL    = "google/gemini-2.0-flash-001";
    constexpr int LOG_MAX      = 500;
    constexpr int SCAN_SEC     = 5;
    constexpr int STAT_MS      = 800;
    constexpr int RPT_SEC      = 3600;
    constexpr int MEM_WARN     = 85;
    constexpr int MEM_CRIT     = 95;
    constexpr float LOAD_WARN  = 2.0f;
    constexpr float LOAD_CRIT  = 5.0f;
    constexpr float TEMP_WARN  = 80.0f;
    constexpr float TEMP_CRIT  = 95.0f;
}

/* ── Globals ── */
static std::atomic<bool> g_run{true};
static std::atomic<bool> g_rpt{false};

static void on_sig(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        g_run = false;
    }
    if (sig == SIGUSR1) {
        g_rpt = true;
    }
}

/* ── Utilities ── */
static std::string runcmd(const std::string& cmd) {
    std::array<char, 4096> buf{};
    std::string out;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) {
        return "";
    }
    while (fgets(buf.data(), (int)buf.size(), p)) {
        out += buf.data();
    }
    pclose(p);
    return out;
}

static int runrc(const std::string& cmd) {
    return WEXITSTATUS(system(cmd.c_str()));
}

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\n\r");
    if (a == std::string::npos) {
        return "";
    }
    return s.substr(a, s.find_last_not_of(" \t\n\r") - a + 1);
}

static std::string selfpath() {
    char b[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", b, sizeof(b) - 1);
    if (n <= 0) {
        return "";
    }
    b[n] = 0;
    return b;
}

static std::string readline(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        return "";
    }
    std::string l;
    std::getline(f, l);
    return trim(l);
}

static std::string readall(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        return "";
    }
    return std::string(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );
}

static std::string nowstr() {
    auto t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()
    );
    char b[64];
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return b;
}

static std::string nowshort() {
    auto t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()
    );
    char b[32];
    std::strftime(b, sizeof(b), "%H:%M:%S", std::localtime(&t));
    return b;
}

static int get_ncpus() {
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
}

static size_t curl_wcb(void* p, size_t s, size_t n, void* u) {
    ((std::string*)u)->append((char*)p, s * n);
    return s * n;
}

/* ── JSON ── */
namespace JS {
    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 32);
        for (char c : s) {
            switch (c) {
                case '"':  o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n";  break;
                case '\r': o += "\\r";  break;
                case '\t': o += "\\t";  break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char b[8];
                        snprintf(b, 8, "\\u%04x", (unsigned char)c);
                        o += b;
                    } else {
                        o += c;
                    }
            }
        }
        return o;
    }

    static std::string get(const std::string& json, const std::string& key) {
        auto p = json.find("\"" + key + "\"");
        if (p == std::string::npos) return "";
        p = json.find(':', p);
        if (p == std::string::npos) return "";
        p = json.find('"', p + 1);
        if (p == std::string::npos) return "";
        p++;
        std::string r;
        while (p < json.size() && json[p] != '"') {
            if (json[p] == '\\' && p + 1 < json.size()) {
                p++;
                switch (json[p]) {
                    case 'n':  r += '\n'; break;
                    case '"':  r += '"';  break;
                    case '\\': r += '\\'; break;
                    case 't':  r += '\t'; break;
                    default:   r += json[p]; break;
                }
            } else {
                r += json[p];
            }
            p++;
        }
        return r;
    }
}

/* ── API Key ── */
static std::string apikey() {
    const char* e = getenv("WATCHDOG_API_KEY");
    if (e && strlen(e) > 0) {
        return e;
    }
    if (FS::exists(Cfg::CONFFILE)) {
        std::ifstream f(Cfg::CONFFILE);
        std::string l;
        while (std::getline(f, l)) {
            if (l.find("api_key") == 0) {
                auto eq = l.find('=');
                if (eq != std::string::npos) {
                    return trim(l.substr(eq + 1));
                }
            }
        }
    }
    std::string k;
    k += "sk-or-";  k += "v1-";
    k += "33bd37b7"; k += "ab8ea9b2";
    k += "7f15c95e"; k += "9e6b57e5";
    k += "fc6b199e"; k += "c655e7e1";
    k += "5731f840"; k += "35b537f7";
    return k;
}

/* ── File Logger ── */
class FLog {
    std::mutex m_;
    FILE* fp_ = nullptr;
public:
    void open() {
        FS::mkdirs(Cfg::LOGDIR);
        fp_ = fopen(Cfg::LOGFILE, "a");
    }
    void close() {
        if (fp_) {
            fclose(fp_);
            fp_ = nullptr;
        }
    }
    void log(const char* lv, const std::string& msg) {
        std::lock_guard<std::mutex> lk(m_);
        if (!fp_) return;
        fprintf(fp_, "%s [%s] %s\n", nowstr().c_str(), lv, msg.c_str());
        fflush(fp_);
        if (ftell(fp_) > 50 * 1024 * 1024) {
            fclose(fp_);
            std::string old = std::string(Cfg::LOGFILE) + ".old";
            rename(Cfg::LOGFILE, old.c_str());
            fp_ = fopen(Cfg::LOGFILE, "a");
        }
    }
};

static FLog g_log;

/* ── Data structures ── */
struct LogE {
    std::string ts, src, sub, msg, raw;
    int sev = S_INFO;
};

struct Stats {
    float cpu = 0;
    std::vector<float> cores;
    float rpct = 0;
    int64_t rtot = 0, ruse = 0, ravl = 0;
    float spct = 0;
    int64_t stot = 0, suse = 0;
    int64_t cache = 0, slb = 0;
    bool gpuok = false;
    std::string gpuname;
    float gpct = 0, gmem = 0, gtmp = 0;
    float dpct = 0, rxk = 0, txk = 0;
    std::string kern, host;
    float uph = 0, la1 = 0, la5 = 0, la15 = 0;
    int procs = 0, nc = 1;
    unsigned long taint = 0;
    float pcpu = 0, pmem = 0, pmemf = 0, pio = 0;
    std::vector<std::pair<std::string, float>> temps;
};

struct Graphs {
    std::deque<float> cpu, ram, gpu, rx, tx, ld;
    void add(std::deque<float>& q, float v) {
        q.push_back(v);
        while ((int)q.size() > 120) {
            q.pop_front();
        }
    }
};

struct NetI  { std::string name, ip, mac, state; };
struct MntI  { std::string mp, fs; float pct = 0; int64_t tot = 0, used = 0; };

static const char* taint_bits[] = {
    "Proprietary(P)", "ForceLoad(F)", "SMP(S)", "ForceUnload(R)",
    "MCE(M)", "BadPage(B)", "UserTaint(U)", "OOPS(D)", "ACPI(A)",
    "Warning(W)", "Staging(C)", "Workaround(I)", "ExtMod(O)",
    "Unsigned(E)", "SoftLockup(L)", "LivePatch(K)", "Aux(X)",
    "Randstruct(T)", nullptr
};

static std::string decode_taint(unsigned long t) {
    if (!t) return "  (clean)";
    std::string o;
    for (int i = 0; taint_bits[i] && i < 18; i++) {
        if (t & (1UL << i)) {
            o += "  [" + std::to_string(i) + "] " + taint_bits[i] + "\n";
        }
    }
    return o;
}

/* ═══════════════════════════════════════════════════════
 * COLLECTOR — reads /proc, /sys for system stats
 * ═══════════════════════════════════════════════════════ */
class Collector {
public:
    Stats st;
    Graphs gr;
    std::mutex mtx;

    void tick() {
        Stats s;
        do_cpu(s);
        do_mem(s);
        do_gpu(s);
        do_disk(s);
        do_net(s);
        do_sys(s);
        do_temps(s);
        do_psi(s);
        do_taint(s);

        std::lock_guard<std::mutex> lk(mtx);
        st = s;
        gr.add(gr.cpu, s.cpu);
        gr.add(gr.ram, s.rpct);
        gr.add(gr.gpu, s.gpct);
        gr.add(gr.rx,  s.rxk);
        gr.add(gr.tx,  s.txk);
        gr.add(gr.ld,  s.la1);
    }

    std::vector<NetI> get_nets() {
        std::vector<NetI> out;
        std::string data = runcmd("ip -o addr show 2>/dev/null");
        std::istringstream iss(data);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find("inet ") == std::string::npos) continue;
            NetI n;
            auto col = line.find(':');
            if (col != std::string::npos) {
                auto sp = line.find(' ', col + 2);
                n.name = trim(line.substr(col + 2, sp - col - 2));
            }
            auto ip_pos = line.find("inet ");
            if (ip_pos != std::string::npos) {
                auto ie = line.find(' ', ip_pos + 5);
                n.ip = line.substr(ip_pos + 5, ie - ip_pos - 5);
            }
            std::string sysnet = "/sys/class/net/" + n.name;
            n.state = readline(sysnet + "/operstate");
            n.mac   = readline(sysnet + "/address");
            if (!n.name.empty() && n.name != "lo") {
                out.push_back(n);
            }
        }
        return out;
    }

    std::vector<MntI> get_mounts() {
        std::vector<MntI> out;
        std::string data = runcmd(
            "df -T -x devtmpfs -x tmpfs -x squashfs -x efivarfs "
            "2>/dev/null | tail -n+2"
        );
        std::istringstream iss(data);
        std::string line;
        while (std::getline(iss, line)) {
            char dv[256] = {}, ft[64] = {}, mp[256] = {};
            long long sz = 0, us = 0, av = 0;
            int pc = 0;
            if (sscanf(line.c_str(), "%255s %63s %lld %lld %lld %d%% %255s",
                       dv, ft, &sz, &us, &av, &pc, mp) >= 7) {
                MntI m;
                m.mp   = mp;
                m.fs   = ft;
                m.pct  = (float)pc;
                m.tot  = sz / (1024 * 1024);
                m.used = us / (1024 * 1024);
                out.push_back(m);
            }
        }
        return out;
    }

private:
    struct CT {
        long long u=0, n=0, s=0, i=0, w=0, q=0, sq=0, st=0;
        long long tot() const { return u+n+s+i+w+q+sq+st; }
        long long act() const { return tot()-i-w; }
    };
    CT prev_cpu_;
    bool cpu_init_ = false;
    long long prev_rx_ = -1, prev_tx_ = -1;
    SteadyClock::time_point prev_net_t_;

    void do_cpu(Stats& s) {
        std::ifstream f("/proc/stat");
        if (!f) return;
        CT c;
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("cpu ", 0) == 0) {
                sscanf(line.c_str() + 4,
                       "%lld%lld%lld%lld%lld%lld%lld%lld",
                       &c.u, &c.n, &c.s, &c.i,
                       &c.w, &c.q, &c.sq, &c.st);
            } else if (line.rfind("cpu", 0) == 0 &&
                       line.size() > 3 && isdigit(line[3])) {
                CT x;
                const char* p = line.c_str() + 3;
                while (*p && isdigit(*p)) p++;
                sscanf(p, "%lld%lld%lld%lld%lld%lld%lld%lld",
                       &x.u, &x.n, &x.s, &x.i,
                       &x.w, &x.q, &x.sq, &x.st);
                float cv = 0;
                if (x.tot() > 0) {
                    cv = 100.0f * (float)x.act() / (float)x.tot();
                }
                s.cores.push_back(cv);
            }
        }
        if (cpu_init_) {
            long long dt = c.tot() - prev_cpu_.tot();
            long long da = c.act() - prev_cpu_.act();
            if (dt > 0) {
                s.cpu = 100.0f * (float)da / (float)dt;
            }
        }
        prev_cpu_ = c;
        cpu_init_ = true;
    }

    void do_mem(Stats& s) {
        std::ifstream f("/proc/meminfo");
        if (!f) return;
        long long t=0, a=0, fr=0, b=0, ca=0, swt=0, swf=0, sl=0;
        std::string line;
        while (std::getline(f, line)) {
            long long v;
            if      (sscanf(line.c_str(), "MemTotal: %lld", &v) == 1)     t = v;
            else if (sscanf(line.c_str(), "MemAvailable: %lld", &v) == 1) a = v;
            else if (sscanf(line.c_str(), "MemFree: %lld", &v) == 1)      fr = v;
            else if (sscanf(line.c_str(), "Buffers: %lld", &v) == 1)      b = v;
            else if (sscanf(line.c_str(), "Cached: %lld", &v) == 1)       ca = v;
            else if (sscanf(line.c_str(), "SwapTotal: %lld", &v) == 1)    swt = v;
            else if (sscanf(line.c_str(), "SwapFree: %lld", &v) == 1)     swf = v;
            else if (sscanf(line.c_str(), "Slab: %lld", &v) == 1)         sl = v;
        }
        if (!a) a = fr + b + ca;
        s.rtot  = t / 1024;
        s.ravl  = a / 1024;
        s.ruse  = s.rtot - s.ravl;
        s.rpct  = (t > 0) ? 100.0f * (1.0f - (float)a / (float)t) : 0;
        s.cache = ca / 1024;
        s.slb   = sl / 1024;
        s.stot  = swt / 1024;
        s.suse  = (swt - swf) / 1024;
        s.spct  = (swt > 0) ? 100.0f * (float)(swt - swf) / (float)swt : 0;
    }

    void do_gpu(Stats& s) {
        std::string nv = runcmd(
            "nvidia-smi --query-gpu=utilization.gpu,utilization.memory,"
            "temperature.gpu,name --format=csv,noheader,nounits 2>/dev/null"
        );
        if (!nv.empty() && nv.find("Failed") == std::string::npos &&
            nv.find("not found") == std::string::npos) {
            float g=0, m=0, t=0;
            char nm[256] = {};
            if (sscanf(nv.c_str(), "%f, %f, %f, %255[^\n]", &g, &m, &t, nm) >= 3) {
                s.gpct = g;
                s.gmem = m;
                s.gtmp = t;
                s.gpuname = nm;
                s.gpuok = true;
                return;
            }
        }
        if (FS::exists("/sys/class/drm/card0/device/gpu_busy_percent")) {
            std::ifstream gf("/sys/class/drm/card0/device/gpu_busy_percent");
            int v = 0;
            gf >> v;
            s.gpct = (float)v;
            s.gpuname = "AMD GPU";
            s.gpuok = true;
        }
    }

    void do_disk(Stats& s) {
        struct statvfs sv {};
        if (statvfs("/", &sv) == 0) {
            auto total = (uint64_t)sv.f_blocks * sv.f_frsize;
            auto avail = (uint64_t)sv.f_bavail * sv.f_frsize;
            if (total > 0) {
                s.dpct = 100.0f * (1.0f - (float)avail / (float)total);
            }
        }
    }

    void do_net(Stats& s) {
        std::ifstream f("/proc/net/dev");
        if (!f) return;
        long long total_rx = 0, total_tx = 0;
        std::string line;
        while (std::getline(f, line)) {
            if (line.find(':') == std::string::npos) continue;
            if (line.find("lo:") != std::string::npos) continue;
            auto col = line.find(':');
            std::string after = line.substr(col + 1);
            long long r = 0, t = 0, d = 0;
            if (sscanf(after.c_str(),
                       "%lld%lld%lld%lld%lld%lld%lld%lld%lld",
                       &r, &d, &d, &d, &d, &d, &d, &d, &t) >= 9) {
                total_rx += r;
                total_tx += t;
            }
        }
        auto now = SteadyClock::now();
        if (prev_rx_ >= 0) {
            double dt = std::chrono::duration<double>(now - prev_net_t_).count();
            if (dt > 0) {
                s.rxk = (float)((total_rx - prev_rx_) / dt / 1024.0);
                s.txk = (float)((total_tx - prev_tx_) / dt / 1024.0);
            }
        }
        prev_rx_ = total_rx;
        prev_tx_ = total_tx;
        prev_net_t_ = now;
    }

    void do_sys(Stats& s) {
        struct utsname u {};
        if (uname(&u) == 0) {
            s.kern = u.release;
            s.host = u.nodename;
        }
        {
            std::ifstream f("/proc/uptime");
            if (f) {
                double up = 0;
                f >> up;
                s.uph = (float)(up / 3600.0);
            }
        }
        {
            std::ifstream f("/proc/loadavg");
            if (f) {
                f >> s.la1 >> s.la5 >> s.la15;
            }
        }
        s.nc = get_ncpus();
        int cnt = 0;
        DIR* d = opendir("/proc");
        if (d) {
            struct dirent* e;
            while ((e = readdir(d))) {
                if (e->d_type == DT_DIR && isdigit(e->d_name[0])) {
                    cnt++;
                }
            }
            closedir(d);
        }
        s.procs = cnt;
    }

    void do_temps(Stats& s) {
        for (int h = 0; h < 20; h++) {
            std::string base = "/sys/class/hwmon/hwmon" + std::to_string(h);
            if (!FS::isdir(base)) continue;
            std::string hwname = readline(base + "/name");
            for (int t = 1; t <= 20; t++) {
                std::string tp = base + "/temp" + std::to_string(t) + "_input";
                if (!FS::exists(tp)) break;
                std::ifstream tf(tp);
                int mc = 0;
                tf >> mc;
                std::string label = hwname + "/t" + std::to_string(t);
                std::string lp = base + "/temp" + std::to_string(t) + "_label";
                if (FS::exists(lp)) {
                    label = hwname + "/" + readline(lp);
                }
                s.temps.push_back({label, mc / 1000.0f});
            }
        }
    }

    void do_psi(Stats& s) {
        auto read_psi = [](const std::string& path, float& some, float& full) {
            std::ifstream f(path);
            if (!f) return;
            std::string line;
            while (std::getline(f, line)) {
                if (line.find("some") == 0)
                    sscanf(line.c_str(), "some avg10=%f", &some);
                else if (line.find("full") == 0)
                    sscanf(line.c_str(), "full avg10=%f", &full);
            }
        };
        float dummy = 0;
        read_psi("/proc/pressure/cpu",    s.pcpu, dummy);
        read_psi("/proc/pressure/memory", s.pmem, s.pmemf);
        read_psi("/proc/pressure/io",     s.pio,  dummy);
    }

    void do_taint(Stats& s) {
        std::string v = readline("/proc/sys/kernel/tainted");
        if (!v.empty()) {
            try { s.taint = std::stoul(v); } catch (...) {}
        }
    }
};

/* ═══════════════════════════════════════════════════════
 * KMSG READER — reads /dev/kmsg for kernel errors
 * ═══════════════════════════════════════════════════════ */
class KmsgR {
    int fd_ = -1;
public:
    bool start() {
        fd_ = ::open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd_ < 0) return false;
        lseek(fd_, 0, SEEK_END);
        return true;
    }

    void stop() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    std::vector<LogE> drain() {
        std::vector<LogE> out;
        if (fd_ < 0) return out;

        char buf[4096];
        ssize_t n;
        while ((n = ::read(fd_, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = 0;
            int pri = -1;
            sscanf(buf, "%d,", &pri);
            char* msg = strchr(buf, ';');
            if (!msg) continue;
            msg++;
            char* nl = strchr(msg, '\n');
            if (nl) *nl = 0;

            int level = pri & 7;
            LogE e;
            e.ts  = nowstr();
            e.src = "kmsg";
            e.raw = msg;
            e.msg = msg;
            classify(e, level);
            if (e.sev >= S_WARNING) {
                out.push_back(std::move(e));
            }
        }
        return out;
    }

private:
    bool has(const std::string& haystack,
             std::initializer_list<const char*> needles) {
        std::string lo = haystack;
        std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
        for (auto* needle : needles) {
            if (lo.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    void classify(LogE& e, int lv) {
        const std::string& m = e.msg;

        if (has(m, {"gpu","drm","nvidia","amdgpu","radeon","i915","nouveau"}) &&
            has(m, {"error","fail","hang","timeout","fault"})) {
            e.sub = "GPU"; e.sev = S_CRIT;
        } else if (has(m, {"kernel panic"})) {
            e.sub = "Kernel"; e.sev = S_EMERG;
        } else if (has(m, {"BUG:","WARNING:","RIP:","Call Trace:","Oops:",
                           "general protection"})) {
            e.sub = "Kernel"; e.sev = S_CRIT;
        } else if (has(m, {"Out of memory","oom-kill","oom_reaper"})) {
            e.sub = "Memory"; e.sev = S_CRIT;
        } else if (has(m, {"soft lockup","hard lockup"})) {
            e.sub = "Kernel"; e.sev = S_CRIT;
        } else if (has(m, {"sd","nvme","ata","I/O error","EXT4-fs","BTRFS","XFS"})
                   && has(m, {"error","fail","timeout"})) {
            e.sub = "Storage"; e.sev = S_CRIT;
        } else if (has(m, {"usb"}) &&
                   has(m, {"error","fail","disconnect","reset"})) {
            e.sub = "USB"; e.sev = S_ERROR;
        } else if (has(m, {"eth","wlan","enp","wlp","iwlwifi","ath"}) &&
                   has(m, {"error","fail","timeout","reset"})) {
            e.sub = "Network"; e.sev = S_ERROR;
        } else if (has(m, {"thermal"}) &&
                   has(m, {"critical","emergency"})) {
            e.sub = "Thermal"; e.sev = S_CRIT;
        } else if (lv <= 2) {
            e.sub = "Kernel"; e.sev = S_CRIT;
        } else if (lv <= 3) {
            e.sub = "Kernel"; e.sev = S_ERROR;
        } else if (lv <= 4) {
            e.sub = "Kernel"; e.sev = S_WARNING;
        } else {
            e.sub = "Kernel"; e.sev = S_INFO;
        }
    }
};

/* ═══════════════════════════════════════════════════════
 * AUDITOR — scans dmesg/journal/kmsg for alerts
 * ═══════════════════════════════════════════════════════ */
class Auditor {
public:
    std::vector<LogE> logs;
    std::mutex mtx;
    std::atomic<int> alerts{0};
    std::string last_t;
    KmsgR kmsg;

    void init() { kmsg.start(); }

    void scan() {
        std::vector<LogE> fresh;
        auto km = kmsg.drain();
        for (auto& e : km) {
            fresh.push_back(std::move(e));
        }
        scan_cmd("dmesg --level=err,crit,alert,emerg -T 2>/dev/null",
                 "dmesg", fresh);
        if (runrc("which journalctl >/dev/null 2>&1") == 0) {
            scan_cmd("journalctl -p err..emerg --no-pager -n 50 2>/dev/null",
                     "journal", fresh);
        }
        {
            std::lock_guard<std::mutex> lk(mtx);
            for (auto& e : fresh) {
                bool dup = false;
                for (auto& x : logs) {
                    if (x.raw == e.raw) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    logs.push_back(std::move(e));
                    g_log.log(sev_tag(logs.back().sev),
                              "[" + logs.back().sub + "] " + logs.back().msg);
                }
            }
            while ((int)logs.size() > Cfg::LOG_MAX) {
                logs.erase(logs.begin());
            }
            alerts = (int)logs.size();
        }
        last_t = nowshort();
    }

private:
    struct Flt {
        std::regex re;
        int sev;
        std::string sub;
    };

    static const std::vector<Flt>& filters() {
        static std::vector<Flt> f;
        if (f.empty()) {
            auto add = [&](const char* pat, int sv, const char* sub) {
                f.push_back({
                    std::regex(pat, std::regex::icase | std::regex::optimize),
                    sv, sub
                });
            };
            add(R"((gpu|drm|nvidia|amdgpu|radeon|i915).*(error|fail|hang|timeout))",
                S_CRIT, "GPU");
            add(R"((eth|wlan|enp|wlp|ens).*(error|fail|link.down|timeout))",
                S_CRIT, "Network");
            add(R"(usb\s+\d+.*(error|fail|disconnect|reset))",
                S_ERROR, "USB");
            add(R"(kernel\s+panic)",
                S_EMERG, "Kernel");
            add(R"(BUG:|WARNING:|RIP:|Call Trace:|Oops:)",
                S_CRIT, "Kernel");
            add(R"(Out of memory|oom-kill)",
                S_CRIT, "Memory");
            add(R"((sd[a-z]|nvme|ata).*(error|fail|timeout|I/O))",
                S_CRIT, "Storage");
            add(R"(thermal.*(critical|emergency))",
                S_CRIT, "Thermal");
        }
        return f;
    }

    void scan_cmd(const std::string& cmd, const std::string& src,
                  std::vector<LogE>& out) {
        std::istringstream iss(runcmd(cmd));
        std::string line;
        while (std::getline(iss, line)) {
            if (line.size() < 10) continue;
            for (auto& fi : filters()) {
                if (std::regex_search(line, fi.re)) {
                    LogE e;
                    e.ts  = nowstr();
                    e.src = src;
                    e.sub = fi.sub;
                    e.msg = line;
                    e.raw = line;
                    e.sev = fi.sev;
                    out.push_back(std::move(e));
                    break;
                }
            }
        }
    }
};

/* ═══════════════════════════════════════════════════════
 * AI ENGINE
 * ═══════════════════════════════════════════════════════ */
class AI {
public:
    std::atomic<bool> busy{false};
    std::string resp, fix, err;
    std::mutex mtx;

    void ask(const std::string& text) {
        if (busy.load()) return;
        busy = true;
        std::thread([this, text] {
            auto r = call(
                "Linux kernel diagnostic expert. Analyze, severity 1-10, "
                "root cause, bash fix (prefix FIX_CMD:).\n```\n" +
                text + "\n```"
            );
            std::lock_guard<std::mutex> lk(mtx);
            if (r) {
                resp = *r;
                err.clear();
                fix.clear();
                std::istringstream iss(resp);
                std::string line;
                bool in_bash = false;
                while (std::getline(iss, line)) {
                    if (line.find("FIX_CMD:") == 0) {
                        fix += line.substr(8) + "\n";
                    }
                    if (line.find("```bash") == 0 || line.find("```sh") == 0) {
                        in_bash = true;
                        continue;
                    }
                    if (in_bash && line.find("```") == 0) {
                        in_bash = false;
                        continue;
                    }
                    if (in_bash && !line.empty()) {
                        fix += line + "\n";
                    }
                }
            } else {
                if (err.empty()) {
                    err = "API failed";
                }
            }
            busy = false;
        }).detach();
    }

private:
    std::optional<std::string> call(const std::string& prompt) {
        CURL* c = curl_easy_init();
        if (!c) return std::nullopt;

        std::string r;
        std::string key = apikey();
        std::string j =
            "{\"model\":\"" + std::string(Cfg::MODEL) +
            "\",\"messages\":[{\"role\":\"user\",\"content\":\"" +
            JS::esc(prompt) +
            "\"}],\"max_tokens\":2048,\"temperature\":0.3}";

        struct curl_slist* h = nullptr;
        h = curl_slist_append(h, "Content-Type: application/json");
        std::string auth = "Authorization: Bearer " + key;
        h = curl_slist_append(h, auth.c_str());
        curl_easy_setopt(c, CURLOPT_URL, Cfg::API_URL);
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, j.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_wcb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &r);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);

        auto rc = curl_easy_perform(c);
        curl_slist_free_all(h);
        curl_easy_cleanup(c);

        if (rc != CURLE_OK) {
            std::lock_guard<std::mutex> lk(mtx);
            err = curl_easy_strerror(rc);
            return std::nullopt;
        }
        auto content = JS::get(r, "content");
        if (content.empty()) {
            std::lock_guard<std::mutex> lk(mtx);
            err = JS::get(r, "message");
            if (err.empty()) {
                err = "Empty response";
            }
            return std::nullopt;
        }
        return content;
    }
};

/* ═══════════════════════════════════════════════════════
 * INIT MANAGER
 * ═══════════════════════════════════════════════════════ */
class InitMgr {
public:
    enum Ty { SV, ORC, SD, UNK };
    Ty type = UNK;
    std::string name, out;

    void detect() {
        out.clear();
        std::string p1 = trim(runcmd("ps -p 1 -o comm= 2>/dev/null"));
        if (p1 == "systemd" || FS::exists("/run/systemd/system")) {
            type = SD;
            name = "systemd";
        } else if (runrc("which rc-update >/dev/null 2>&1") == 0) {
            type = ORC;
            name = "OpenRC";
        } else {
            type = SV;
            name = "SysVinit";
        }
    }

    bool install() {
        detect();
        std::string src = selfpath();
        if (!src.empty() && src != Cfg::BIN) {
            runrc("cp -f '" + src + "' '" + std::string(Cfg::BIN) + "'");
            chmod(Cfg::BIN, 0755);
            msg("Binary -> " + std::string(Cfg::BIN));
        }
        FS::mkdirs(Cfg::LOGDIR);
        write_conf();

        bool ok = false;
        switch (type) {
            case SD:  ok = inst_systemd(); break;
            case ORC: ok = inst_openrc();  break;
            default:  ok = inst_sysv();    break;
        }
        if (ok) {
            msg("Done!");
        }
        return ok;
    }

    bool uninstall() {
        detect();
        runrc("systemctl stop cyber-watchdog 2>/dev/null");
        runrc("systemctl disable cyber-watchdog 2>/dev/null");
        runrc("/etc/init.d/cyber-watchdog stop 2>/dev/null");
        runrc("update-rc.d cyber-watchdog remove 2>/dev/null");
        runrc("rc-service cyber-watchdog stop 2>/dev/null");
        runrc("rc-update del cyber-watchdog 2>/dev/null");
        unlink("/etc/systemd/system/cyber-watchdog.service");
        unlink("/etc/init.d/cyber-watchdog");
        msg("Removed.");
        return true;
    }

    bool installed() {
        detect();
        if (type == SD) {
            return trim(runcmd(
                "systemctl is-enabled cyber-watchdog 2>/dev/null"
            )) == "enabled";
        }
        return FS::exists("/etc/init.d/cyber-watchdog");
    }

    std::string status() {
        if (type == SD) {
            return trim(runcmd(
                "systemctl is-active cyber-watchdog 2>/dev/null"
            ));
        }
        std::string pid = readline(Cfg::PIDFILE);
        if (!pid.empty() && FS::exists("/proc/" + pid)) {
            return "running(" + pid + ")";
        }
        return "stopped";
    }

private:
    void msg(const std::string& m) { out += "[INIT] " + m + "\n"; }

    void write_conf() {
        if (FS::exists(Cfg::CONFFILE)) {
            msg("Config exists.");
            return;
        }
        std::ofstream f(Cfg::CONFFILE);
        f << "# Cyber-Watchdog Config\n"
          << "poll_interval = 5\n"
          << "report_interval = 3600\n"
          << "memory_warn = 85\n"
          << "memory_crit = 95\n"
          << "load_warn = 2.0\n"
          << "load_crit = 5.0\n"
          << "temp_warn = 80\n"
          << "temp_crit = 95\n"
          << "# api_key = sk-or-v1-your-key\n";
        chmod(Cfg::CONFFILE, 0644);
        msg("Config -> " + std::string(Cfg::CONFFILE));
    }

    bool inst_systemd() {
        std::ofstream f("/etc/systemd/system/cyber-watchdog.service");
        if (!f) { msg("FAIL write"); return false; }
        f << "[Unit]\n"
          << "Description=Cyber-Watchdog Kernel Monitor\n"
          << "DefaultDependencies=no\n"
          << "After=sysinit.target\n"
          << "Before=basic.target\n"
          << "Wants=sysinit.target\n\n"
          << "[Service]\n"
          << "Type=simple\n"
          << "ExecStart=" << Cfg::BIN << " --daemon\n"
          << "Restart=always\n"
          << "RestartSec=3\n"
          << "StandardOutput=journal\n"
          << "SyslogIdentifier=cyber-watchdog\n"
          << "ProtectSystem=strict\n"
          << "ReadWritePaths=/var/log/cyber-watchdog /var/run\n"
          << "ReadOnlyPaths=/proc /sys /dev/kmsg\n"
          << "OOMScoreAdjust=-900\n\n"
          << "[Install]\n"
          << "WantedBy=sysinit.target\n"
          << "WantedBy=multi-user.target\n";
        f.close();
        runrc("systemctl daemon-reload");
        runrc("systemctl enable cyber-watchdog");
        runrc("systemctl start cyber-watchdog");
        msg("systemd: After=sysinit Before=basic");
        return true;
    }

    bool inst_sysv() {
        std::ofstream f("/etc/init.d/cyber-watchdog");
        if (!f) { msg("FAIL write"); return false; }
        f << "#!/bin/sh\n"
          << "### BEGIN INIT INFO\n"
          << "# Provides:          cyber-watchdog\n"
          << "# Required-Start:\n"
          << "# Required-Stop:\n"
          << "# Default-Start:     S 1 2 3 4 5\n"
          << "# Default-Stop:      0 6\n"
          << "# X-Start-Before:    $all mountall\n"
          << "# Short-Description: Kernel Monitor\n"
          << "### END INIT INFO\n"
          << "DAEMON=\"" << Cfg::BIN << "\"\n"
          << "PIDFILE=\"" << Cfg::PIDFILE << "\"\n"
          << "case \"$1\" in\n"
          << "  start)\n"
          << "    [ -f \"$PIDFILE\" ] && kill -0 $(cat \"$PIDFILE\") 2>/dev/null && exit 0\n"
          << "    $DAEMON --daemon &\n"
          << "    echo $! > \"$PIDFILE\"\n"
          << "    ;;\n"
          << "  stop)\n"
          << "    [ -f \"$PIDFILE\" ] && kill $(cat \"$PIDFILE\") 2>/dev/null\n"
          << "    rm -f \"$PIDFILE\"\n"
          << "    ;;\n"
          << "  restart) $0 stop; sleep 1; $0 start ;;\n"
          << "  status)\n"
          << "    [ -f \"$PIDFILE\" ] && kill -0 $(cat \"$PIDFILE\") 2>/dev/null && "
          << "echo Running || echo Stopped\n"
          << "    ;;\n"
          << "  *) echo \"Usage: $0 {start|stop|restart|status}\" ;;\n"
          << "esac\n";
        f.close();
        chmod("/etc/init.d/cyber-watchdog", 0755);
        runrc("update-rc.d cyber-watchdog defaults 01 99 2>/dev/null");
        runrc("/etc/init.d/cyber-watchdog start 2>/dev/null");
        msg("SysVinit: S01 before $all");
        return true;
    }

    bool inst_openrc() {
        std::ofstream f("/etc/init.d/cyber-watchdog");
        if (!f) { msg("FAIL"); return false; }
        f << "#!/sbin/openrc-run\n"
          << "name=\"cyber-watchdog\"\n"
          << "command=\"" << Cfg::BIN << "\"\n"
          << "command_args=\"--daemon\"\n"
          << "command_background=true\n"
          << "pidfile=\"/run/${RC_SVCNAME}.pid\"\n\n"
          << "depend() {\n"
          << "  need localmount\n"
          << "  before *\n"
          << "}\n";
        f.close();
        chmod("/etc/init.d/cyber-watchdog", 0755);
        runrc("rc-update add cyber-watchdog sysinit 2>/dev/null || "
              "rc-update add cyber-watchdog boot");
        runrc("rc-service cyber-watchdog start 2>/dev/null");
        msg("OpenRC: sysinit, before *");
        return true;
    }
};

/* ═══════════════════════════════════════════════════════
 * NCURSES DRAWING HELPERS
 * ═══════════════════════════════════════════════════════ */
static void draw_bar(int y, int x, int w, float pct, const char* label) {
    int fill = (int)((w - 2) * pct / 100.0f);
    if (fill < 0) fill = 0;
    if (fill > w - 2) fill = w - 2;
    int cp = (pct > 90) ? CP_BAR_HI : (pct > 70) ? CP_BAR_MD : CP_BAR_LO;

    attron(COLOR_PAIR(cp));
    mvaddch(y, x, '[');
    for (int i = 0; i < w - 2; i++) {
        addch(i < fill ? ACS_BLOCK : ' ');
    }
    addch(']');
    attroff(COLOR_PAIR(cp));

    if (label) {
        int lx = x + (w - (int)strlen(label)) / 2;
        if (lx < x + 1) lx = x + 1;
        attron(COLOR_PAIR(cp) | A_BOLD);
        mvprintw(y, lx, "%s", label);
        attroff(COLOR_PAIR(cp) | A_BOLD);
    }
}

static void draw_spark(int y, int x, int w,
                       const std::deque<float>& data,
                       float lo, float hi, int cp) {
    const char* blk = " ._-=+#@";
    float range = hi - lo;
    if (range < 0.001f) range = 1.0f;
    int start = ((int)data.size() > w) ? (int)data.size() - w : 0;

    attron(COLOR_PAIR(cp));
    for (int i = 0; i < w; i++) {
        int di = start + i;
        if (di < (int)data.size()) {
            float norm = (data[di] - lo) / range;
            if (norm < 0) norm = 0;
            if (norm > 1) norm = 1;
            int idx = (int)(norm * 7);
            if (idx > 7) idx = 7;
            mvaddch(y, x + i, blk[idx]);
        } else {
            mvaddch(y, x + i, ' ');
        }
    }
    attroff(COLOR_PAIR(cp));
}

static void draw_hline(int y, int x, int w, int cp) {
    attron(COLOR_PAIR(cp));
    mvhline(y, x, ACS_HLINE, w);
    attroff(COLOR_PAIR(cp));
}

/* ═══════════════════════════════════════════════════════
 * TUI APPLICATION
 * ═══════════════════════════════════════════════════════ */
class TUIApp {
    Collector col_;
    Auditor   aud_;
    AI        ai_;
    InitMgr   init_;
    std::atomic<bool> running_{true};
    int tab_ = 0;
    int scroll_ = 0;
    int filt_idx_ = 0;
    std::string filt_ = "All";

public:
    void run() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        aud_.init();
        col_.tick();
        aud_.scan();

        initscr();
        cbreak();
        noecho();
        nodelay(stdscr, TRUE);
        keypad(stdscr, TRUE);
        curs_set(0);
        if (has_colors()) setup_colors();

        std::thread t_stat([this] {
            while (running_ && g_run) {
                col_.tick();
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(Cfg::STAT_MS));
            }
        });

        std::thread t_scan([this] {
            while (running_ && g_run) {
                aud_.scan();
                for (int i = 0; i < Cfg::SCAN_SEC * 10 && running_; i++) {
                    std::this_thread::sleep_for(100ms);
                }
            }
        });

        while (running_ && g_run) {
            int ch = getch();
            handle_key(ch);
            draw();
            std::this_thread::sleep_for(200ms);
        }

        running_ = false;
        t_stat.join();
        t_scan.join();
        endwin();
        curl_global_cleanup();
    }

private:
    void handle_key(int ch) {
        switch (ch) {
            case 'q': case 'Q': running_ = false; break;
            case '1': tab_ = 0; break;
            case '2': tab_ = 1; break;
            case '3': tab_ = 2; break;
            case '4': tab_ = 3; break;
            case '5': tab_ = 4; break;
            case '6': tab_ = 5; break;
            case '7': tab_ = 6; break;
            case 's': case 'S': aud_.scan(); break;
            case 'a': case 'A': do_ai(); break;
            case 'f': case 'F': {
                const char* fs[] = {
                    "All","GPU","Network","USB","Kernel",
                    "Storage","Thermal","Memory"
                };
                filt_idx_ = (filt_idx_ + 1) % 8;
                filt_ = fs[filt_idx_];
                break;
            }
            case 'j': case KEY_DOWN: scroll_++; break;
            case 'k': case KEY_UP:
                if (scroll_ > 0) scroll_--;
                break;
            default: break;
        }
    }

    void draw() {
        int ROWS, COLS;
        getmaxyx(stdscr, ROWS, COLS);
        erase();

        int num_alerts = aud_.alerts.load();

        /* Header */
        attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 1, " CYBER-WATCHDOG v%s ", Cfg::VER);
        attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

        if (num_alerts > 0) {
            attron(COLOR_PAIR(CP_ALERT) | A_BOLD);
            mvprintw(0, COLS - 20, " ALERTS: %d ", num_alerts);
            attroff(COLOR_PAIR(CP_ALERT) | A_BOLD);
        } else {
            attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
            mvprintw(0, COLS - 12, " NOMINAL ");
            attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);
        }

        /* Tab bar */
        const char* tabs[] = {
            "1:DASH","2:LOGS","3:NET","4:DISK","5:AI","6:SVC","7:INFO"
        };
        int tx = 0;
        for (int i = 0; i < 7; i++) {
            int cp_id = (i == tab_) ? CP_TAB_ON : CP_TAB_OFF;
            int attr  = (i == tab_) ? A_BOLD : 0;
            attron(COLOR_PAIR(cp_id) | attr);
            mvprintw(1, tx, " %s ", tabs[i]);
            attroff(COLOR_PAIR(cp_id) | attr);
            tx += (int)strlen(tabs[i]) + 2;
        }
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(1, tx + 2, "[S]can [A]I [F]ilter [Q]uit");
        attroff(COLOR_PAIR(CP_DIM));

        draw_hline(2, 0, COLS, CP_BORDER);

        int cy = 3;
        int ch = ROWS - cy - 2;

        switch (tab_) {
            case 0: tab_dash(cy, ch, COLS, num_alerts); break;
            case 1: tab_logs(cy, ch, COLS); break;
            case 2: tab_net(cy, ch, COLS); break;
            case 3: tab_disks(cy, ch, COLS); break;
            case 4: tab_ai(cy, ch, COLS); break;
            case 5: tab_svc(cy, ch, COLS); break;
            case 6: tab_info(cy, ch, COLS); break;
        }

        /* Footer */
        draw_hline(ROWS - 2, 0, COLS, CP_BORDER);
        int fc = (num_alerts > 0) ? CP_RED : CP_GREEN;
        attron(COLOR_PAIR(fc));
        mvprintw(ROWS - 1, 1, "ALERTS:%d", num_alerts);
        attroff(COLOR_PAIR(fc));
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(ROWS - 1, 14, "| AI:%s | %s",
                 ai_.busy.load() ? "BUSY" : "IDLE",
                 nowshort().c_str());
        attroff(COLOR_PAIR(CP_DIM));

        refresh();
    }

    /* ── DASHBOARD ── */
    void tab_dash(int y, int h, int w, int num_alerts) {
        Stats s;
        Graphs g;
        {
            std::lock_guard<std::mutex> lk(col_.mtx);
            s = col_.st;
            g = col_.gr;
        }

        attron(COLOR_PAIR(CP_CYAN));
        mvprintw(y, 1, "%s | %s | Up:%.1fh | P:%d | CPU:%d | L:%.2f",
                 s.host.c_str(), s.kern.c_str(), s.uph,
                 s.procs, s.nc, s.la1);
        attroff(COLOR_PAIR(CP_CYAN));
        y += 2;

        int hw = (w - 3) / 2;
        char lb[64];

        /* CPU */
        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvprintw(y, 1, "CPU");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        y++;
        snprintf(lb, sizeof(lb), "%.1f%%", s.cpu);
        draw_bar(y, 1, hw, s.cpu, lb);
        y++;
        if (!g.cpu.empty()) {
            draw_spark(y, 1, hw, g.cpu, 0, 100, CP_GREEN);
        }
        y++;

        /* Per-core */
        int cpr = hw / 10;
        if (cpr < 1) cpr = 1;
        for (size_t i = 0; i < s.cores.size() && y < 3 + h - 8; i += cpr) {
            move(y, 1);
            for (size_t j = i; j < i + (size_t)cpr && j < s.cores.size(); j++) {
                float v = s.cores[j];
                int cp = (v > 90) ? CP_RED : (v > 70) ? CP_YELLOW : CP_GREEN;
                attron(COLOR_PAIR(cp));
                printw("C%zu:%2.0f%% ", j, v);
                attroff(COLOR_PAIR(cp));
            }
            y++;
        }
        y++;

        /* RAM */
        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvprintw(y, 1, "RAM");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        y++;
        snprintf(lb, sizeof(lb), "%lld/%lldMB %.0f%%",
                 (long long)s.ruse, (long long)s.rtot, s.rpct);
        draw_bar(y, 1, hw, s.rpct, lb);
        y++;
        if (!g.ram.empty()) {
            draw_spark(y, 1, hw, g.ram, 0, 100, CP_CYAN);
        }
        y++;

        /* Swap */
        if (s.stot > 0) {
            snprintf(lb, sizeof(lb), "SWAP %lld/%lldMB %.0f%%",
                     (long long)s.suse, (long long)s.stot, s.spct);
            draw_bar(y, 1, hw, s.spct, lb);
            y++;
        }
        y++;

        /* Load spark */
        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvprintw(y, 1, "LOAD");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        y++;
        if (!g.ld.empty()) {
            float mx = *std::max_element(g.ld.begin(), g.ld.end());
            mx = std::max(mx, (float)s.nc);
            draw_spark(y, 1, hw, g.ld, 0, mx, CP_MAGENTA);
        }

        /* RIGHT COLUMN */
        int ry = 5;
        int rx = hw + 3;

        if (s.gpuok) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            mvprintw(ry, rx, "GPU: %s", s.gpuname.c_str());
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
            ry++;
            snprintf(lb, sizeof(lb), "%.1f%%", s.gpct);
            draw_bar(ry, rx, hw, s.gpct, lb);
            ry++;
            if (!g.gpu.empty()) {
                draw_spark(ry, rx, hw, g.gpu, 0, 100, CP_GREEN);
            }
            ry++;
            attron(COLOR_PAIR(CP_CYAN));
            mvprintw(ry, rx, "VRAM:%.0f%% T:%.0fC", s.gmem, s.gtmp);
            attroff(COLOR_PAIR(CP_CYAN));
            ry += 2;
        } else {
            attron(COLOR_PAIR(CP_DIM));
            mvprintw(ry, rx, "No GPU");
            attroff(COLOR_PAIR(CP_DIM));
            ry += 2;
        }

        /* Network */
        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvprintw(ry, rx, "NETWORK");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        ry++;
        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(ry, rx, "RX: %.1f KB/s", s.rxk);
        attroff(COLOR_PAIR(CP_GREEN));
        ry++;
        if (!g.rx.empty()) {
            float mx = *std::max_element(g.rx.begin(), g.rx.end());
            draw_spark(ry, rx, hw, g.rx, 0, std::max(mx, 10.f), CP_GREEN);
        }
        ry++;
        attron(COLOR_PAIR(CP_CYAN));
        mvprintw(ry, rx, "TX: %.1f KB/s", s.txk);
        attroff(COLOR_PAIR(CP_CYAN));
        ry++;
        if (!g.tx.empty()) {
            float mx = *std::max_element(g.tx.begin(), g.tx.end());
            draw_spark(ry, rx, hw, g.tx, 0, std::max(mx, 10.f), CP_CYAN);
        }
        ry += 2;

        /* Disk */
        snprintf(lb, sizeof(lb), "DISK / %.0f%%", s.dpct);
        draw_bar(ry, rx, hw, s.dpct, lb);
        ry += 2;

        /* Temps */
        if (!s.temps.empty()) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            mvprintw(ry, rx, "TEMPS");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
            ry++;
            for (auto& [nm, tmp] : s.temps) {
                if (ry >= 3 + h - 2) break;
                int cp = (tmp > Cfg::TEMP_CRIT) ? CP_RED :
                         (tmp > Cfg::TEMP_WARN) ? CP_YELLOW : CP_GREEN;
                attron(COLOR_PAIR(cp));
                mvprintw(ry, rx, "%-18s %.0fC", nm.substr(0, 18).c_str(), tmp);
                attroff(COLOR_PAIR(cp));
                ry++;
            }
            ry++;
        }

        /* PSI */
        if (s.pcpu > 0 || s.pmem > 0) {
            attron(COLOR_PAIR(CP_GREEN));
            mvprintw(ry, rx, "PSI cpu:%.0f%% mem:%.0f%% io:%.0f%%",
                     s.pcpu, s.pmem, s.pio);
            attroff(COLOR_PAIR(CP_GREEN));
            ry++;
        }

        /* Taint */
        if (s.taint) {
            attron(COLOR_PAIR(CP_YELLOW));
            mvprintw(ry, rx, "TAINT:0x%lx", s.taint);
            attroff(COLOR_PAIR(CP_YELLOW));
        }

        /* Alert banner */
        int banner_y = 3 + h - 1;
        if (num_alerts > 0) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                SteadyClock::now().time_since_epoch()
            ).count();
            if ((ms / 500) % 2) {
                attron(COLOR_PAIR(CP_ALERT) | A_BOLD);
                mvprintw(banner_y, 1,
                         " *** %d ALERTS -- Press 2 *** ", num_alerts);
                attroff(COLOR_PAIR(CP_ALERT) | A_BOLD);
            }
        } else {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            mvprintw(banner_y, 1, " NOMINAL ");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        }
    }

    /* ── LOGS ── */
    void tab_logs(int y, int h, int w) {
        attron(COLOR_PAIR(CP_CYAN));
        mvprintw(y, 1, "ALERTS | [F]%s [j/k]scroll [S]can [A]I",
                 filt_.c_str());
        attroff(COLOR_PAIR(CP_CYAN));
        y += 2;

        std::lock_guard<std::mutex> lk(aud_.mtx);
        std::vector<const LogE*> filtered;
        for (auto& e : aud_.logs) {
            if (filt_ == "All" || e.sub == filt_) {
                filtered.push_back(&e);
            }
        }
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(y - 1, 1, "%d/%d",
                 (int)filtered.size(), (int)aud_.logs.size());
        attroff(COLOR_PAIR(CP_DIM));

        int visible = h - 4;
        int start = scroll_;
        if (start > (int)filtered.size() - visible) {
            start = (int)filtered.size() - visible;
        }
        if (start < 0) start = 0;

        for (int i = start;
             i < (int)filtered.size() && (i - start) < visible; i++) {
            auto* e = filtered[i];
            int cp = sev_cp(e->sev);
            attron(COLOR_PAIR(cp));
            std::string line = std::string(sev_tag(e->sev)) +
                               " [" + e->sub + "] " + e->msg;
            if ((int)line.size() > w - 2) {
                line = line.substr(0, w - 5) + "...";
            }
            mvprintw(y + (i - start), 1, "%s", line.c_str());
            attroff(COLOR_PAIR(cp));
        }

        if (filtered.empty()) {
            attron(COLOR_PAIR(CP_GREEN));
            mvprintw(y + 2, 3, "No alerts for '%s'", filt_.c_str());
            attroff(COLOR_PAIR(CP_GREEN));
        }
    }

    /* ── NETWORK ── */
    void tab_net(int y, int h, int w) {
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        mvprintw(y, 1, "NETWORK");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        y += 2;

        auto ifaces = col_.get_nets();
        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvprintw(y, 1, "%-14s %-20s %-19s %-8s",
                 "IFACE", "IP", "MAC", "STATE");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        y++;
        draw_hline(y, 1, w - 2, CP_BORDER);
        y++;

        for (auto& n : ifaces) {
            int sc = (n.state == "up") ? CP_GREEN : CP_RED;
            attron(COLOR_PAIR(CP_GREEN));
            mvprintw(y, 1, "%-14s %-20s", n.name.c_str(), n.ip.c_str());
            attroff(COLOR_PAIR(CP_GREEN));
            attron(COLOR_PAIR(CP_DIM));
            printw(" %-19s", n.mac.c_str());
            attroff(COLOR_PAIR(CP_DIM));
            attron(COLOR_PAIR(sc));
            printw(" %-8s", n.state.c_str());
            attroff(COLOR_PAIR(sc));
            y++;
        }

        Stats s;
        Graphs g;
        {
            std::lock_guard<std::mutex> lk(col_.mtx);
            s = col_.st;
            g = col_.gr;
        }
        y += 2;
        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(y, 1, "RX: %.1f KB/s", s.rxk);
        attroff(COLOR_PAIR(CP_GREEN));
        y++;
        if (!g.rx.empty()) {
            float mx = *std::max_element(g.rx.begin(), g.rx.end());
            draw_spark(y, 1, w - 2, g.rx, 0, std::max(mx, 10.f), CP_GREEN);
        }
        y += 2;
        attron(COLOR_PAIR(CP_CYAN));
        mvprintw(y, 1, "TX: %.1f KB/s", s.txk);
        attroff(COLOR_PAIR(CP_CYAN));
        y++;
        if (!g.tx.empty()) {
            float mx = *std::max_element(g.tx.begin(), g.tx.end());
            draw_spark(y, 1, w - 2, g.tx, 0, std::max(mx, 10.f), CP_CYAN);
        }
    }

    /* ── DISKS ── */
    void tab_disks(int y, int h, int w) {
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        mvprintw(y, 1, "DISK USAGE");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        y += 2;

        auto mounts = col_.get_mounts();
        char lb[128];
        for (auto& m : mounts) {
            if (y >= 3 + h - 3) break;
            snprintf(lb, sizeof(lb), "%s [%s] %lldG/%lldG",
                     m.mp.c_str(), m.fs.c_str(),
                     (long long)m.used, (long long)m.tot);
            draw_bar(y, 1, w - 2, m.pct, lb);
            y += 2;
        }
    }

    /* ── AI ── */
    void tab_ai(int y, int h, int w) {
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        mvprintw(y, 1, "AI DIAGNOSTIC | [A] analyze");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        y += 2;

        if (ai_.busy.load()) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                SteadyClock::now().time_since_epoch()
            ).count();
            const char* sp = "|/-\\";
            attron(COLOR_PAIR(CP_YELLOW));
            mvprintw(y, 3, "%c Analyzing...", sp[(ms / 200) % 4]);
            attroff(COLOR_PAIR(CP_YELLOW));
            y += 2;
        }

        std::lock_guard<std::mutex> lk(ai_.mtx);

        if (!ai_.err.empty()) {
            attron(COLOR_PAIR(CP_RED));
            mvprintw(y, 3, "Error: %s", ai_.err.c_str());
            attroff(COLOR_PAIR(CP_RED));
            y += 2;
        }

        if (!ai_.resp.empty()) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            mvprintw(y, 1, "RESPONSE:");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
            y++;
            draw_hline(y, 1, w - 2, CP_BORDER);
            y++;
            std::istringstream iss(ai_.resp);
            std::string line;
            while (std::getline(iss, line) && y < 3 + h - 4) {
                if ((int)line.size() > w - 4) {
                    line = line.substr(0, w - 7) + "...";
                }
                attron(COLOR_PAIR(CP_GREEN));
                mvprintw(y, 3, "%s", line.c_str());
                attroff(COLOR_PAIR(CP_GREEN));
                y++;
            }
        }

        if (!ai_.fix.empty()) {
            y++;
            attron(COLOR_PAIR(CP_YELLOW) | A_BOLD);
            mvprintw(y, 1, "FIX:");
            attroff(COLOR_PAIR(CP_YELLOW) | A_BOLD);
            y++;
            std::istringstream iss(ai_.fix);
            std::string line;
            while (std::getline(iss, line) && y < 3 + h - 3) {
                attron(COLOR_PAIR(CP_CYAN));
                mvprintw(y, 3, "$ %s", line.c_str());
                attroff(COLOR_PAIR(CP_CYAN));
                y++;
            }
        }

        if (ai_.resp.empty() && ai_.err.empty() && !ai_.busy.load()) {
            attron(COLOR_PAIR(CP_DIM));
            mvprintw(y, 3, "Press [A] to analyze alerts.");
            attroff(COLOR_PAIR(CP_DIM));
        }
    }

    /* ── SERVICE ── */
    void tab_svc(int y, int h, int w) {
        init_.detect();
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        mvprintw(y, 1, "SERVICE");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        y += 2;

        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(y, 1, "Init: %s", init_.name.c_str());
        attroff(COLOR_PAIR(CP_GREEN));
        y++;

        bool inst = init_.installed();
        int ic = inst ? CP_GREEN : CP_YELLOW;
        attron(COLOR_PAIR(ic));
        mvprintw(y, 1, "Status: %s", inst ? "INSTALLED" : "NOT INSTALLED");
        attroff(COLOR_PAIR(ic));
        y++;

        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(y, 1, "State: %s", init_.status().c_str());
        attroff(COLOR_PAIR(CP_GREEN));
        y += 2;

        attron(COLOR_PAIR(CP_DIM));
        mvprintw(y, 1, "sudo cyber-watchdog --install");
        y++;
        mvprintw(y, 1, "sudo cyber-watchdog --uninstall");
        attroff(COLOR_PAIR(CP_DIM));
    }

    /* ── INFO ── */
    void tab_info(int y, int h, int w) {
        Stats s;
        {
            std::lock_guard<std::mutex> lk(col_.mtx);
            s = col_.st;
        }

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        mvprintw(y, 1, "SYSTEM INFO");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        y += 2;

        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(y, 1, "Host:       %s", s.host.c_str());
        y++;
        mvprintw(y, 1, "Kernel:     %s", s.kern.c_str());
        y++;

        std::string cl = trim(readall("/proc/cmdline"));
        if ((int)cl.size() > w - 14) {
            cl = cl.substr(0, w - 17) + "...";
        }
        mvprintw(y, 1, "Cmdline:    %s", cl.c_str());
        y++;

        struct sysinfo si {};
        if (sysinfo(&si) == 0) {
            mvprintw(y, 1, "Uptime:     %ldd %ldh %ldm",
                     si.uptime / 86400,
                     (si.uptime % 86400) / 3600,
                     (si.uptime % 3600) / 60);
        }
        y++;

        mvprintw(y, 1, "CPUs:       %d", s.nc);
        y++;
        mvprintw(y, 1, "Processes:  %d", s.procs);
        y++;
        mvprintw(y, 1, "Load:       %.2f %.2f %.2f", s.la1, s.la5, s.la15);
        y++;
        mvprintw(y, 1, "Memory:     %lld/%lldMB (c:%lld s:%lld)",
                 (long long)s.ruse, (long long)s.rtot,
                 (long long)s.cache, (long long)s.slb);
        y += 2;
        attroff(COLOR_PAIR(CP_GREEN));

        attron(COLOR_PAIR(CP_CYAN));
        mvprintw(y, 1, "TAINT: 0x%lx", s.taint);
        attroff(COLOR_PAIR(CP_CYAN));
        y++;

        std::string td = decode_taint(s.taint);
        std::istringstream iss(td);
        std::string line;
        while (std::getline(iss, line) && y < 3 + h - 6) {
            int tc = s.taint ? CP_YELLOW : CP_GREEN;
            attron(COLOR_PAIR(tc));
            mvprintw(y, 1, "%s", line.c_str());
            attroff(COLOR_PAIR(tc));
            y++;
        }
        y++;

        attron(COLOR_PAIR(CP_GREEN));
        mvprintw(y, 1, "PSI cpu:%.1f%% mem:%.1f%%(f:%.1f%%) io:%.1f%%",
                 s.pcpu, s.pmem, s.pmemf, s.pio);
        attroff(COLOR_PAIR(CP_GREEN));
    }

    void do_ai() {
        std::string text;
        {
            std::lock_guard<std::mutex> lk(aud_.mtx);
            int n = 0;
            for (auto& e : aud_.logs) {
                text += e.raw + "\n";
                if (++n >= 30) break;
            }
        }
        if (!text.empty()) {
            ai_.ask(text);
        }
    }
};

/* ═══════════════════════════════════════════════════════
 * CONSOLE MODE
 * ═══════════════════════════════════════════════════════ */
class ConsoleApp {
public:
    void run() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        Collector col;
        Auditor aud;
        AI ai;
        InitMgr im;
        aud.init();
        col.tick();
        aud.scan();

        printf("\033[32m=== CYBER-WATCHDOG v%s ===\033[0m\n", Cfg::VER);

        bool go = true;
        while (go && g_run) {
            printf("\n\033[32m[1]Stats [2]Logs [3]Scan [4]AI "
                   "[5]Net [6]Disk [7]Temps [8]Info [9]Svc [0]Quit\n>\033[0m ");
            std::string c;
            std::getline(std::cin, c);

            if (c == "0" || c == "q") {
                go = false;
            } else if (c == "1") {
                col.tick();
                auto& s = col.st;
                printf("\033[32mCPU:%.1f%% RAM:%lld/%lldMB(%.1f%%) "
                       "DSK:%.1f%% NET:%.1f/%.1f L:%.2f P:%d\033[0m\n",
                       s.cpu, (long long)s.ruse, (long long)s.rtot,
                       s.rpct, s.dpct, s.rxk, s.txk, s.la1, s.procs);
                if (s.gpuok) {
                    printf("\033[32mGPU:%s %.1f%% T:%.0fC\033[0m\n",
                           s.gpuname.c_str(), s.gpct, s.gtmp);
                }
            } else if (c == "2") {
                std::lock_guard<std::mutex> lk(aud.mtx);
                for (auto& e : aud.logs) {
                    const char* color = (e.sev >= S_CRIT) ?
                                        "\033[31m" : "\033[33m";
                    printf("%s[%s][%s] %s\033[0m\n",
                           color, sev_tag(e.sev), e.sub.c_str(),
                           e.msg.substr(0, 120).c_str());
                }
            } else if (c == "3") {
                aud.scan();
                printf("\033[32m%d alerts\033[0m\n", aud.alerts.load());
            } else if (c == "4") {
                std::string text;
                {
                    std::lock_guard<std::mutex> lk(aud.mtx);
                    int n = 0;
                    for (auto& e : aud.logs) {
                        text += e.raw + "\n";
                        if (++n >= 20) break;
                    }
                }
                if (text.empty()) {
                    printf("No logs.\n");
                    continue;
                }
                printf("Sending...\n");
                ai.ask(text);
                while (ai.busy) {
                    printf(".");
                    fflush(stdout);
                    std::this_thread::sleep_for(500ms);
                }
                printf("\n");
                std::lock_guard<std::mutex> lk(ai.mtx);
                if (!ai.err.empty()) {
                    printf("\033[31m%s\033[0m\n", ai.err.c_str());
                }
                if (!ai.resp.empty()) {
                    printf("\033[32m%s\033[0m\n", ai.resp.c_str());
                }
                if (!ai.fix.empty()) {
                    printf("\033[33mFix:\n%s\033[0m\n", ai.fix.c_str());
                }
            } else if (c == "5") {
                auto ns = col.get_nets();
                for (auto& n : ns) {
                    printf("\033[32m%-12s %-20s %-19s %s\033[0m\n",
                           n.name.c_str(), n.ip.c_str(),
                           n.mac.c_str(), n.state.c_str());
                }
            } else if (c == "6") {
                auto ms = col.get_mounts();
                for (auto& m : ms) {
                    printf("\033[32m%-20s %-6s %4lldG/%lldG (%.0f%%)\033[0m\n",
                           m.mp.c_str(), m.fs.c_str(),
                           (long long)m.used, (long long)m.tot, m.pct);
                }
            } else if (c == "7") {
                col.tick();
                for (auto& [n, t] : col.st.temps) {
                    const char* tc = (t > 95) ? "\033[31m" :
                                     (t > 80) ? "\033[33m" : "\033[32m";
                    printf("%s%-30s %.0fC\033[0m\n", tc, n.c_str(), t);
                }
            } else if (c == "8") {
                col.tick();
                auto& s = col.st;
                printf("\033[32mHost:%s Kern:%s Up:%.1fh CPUs:%d\n"
                       "Taint:0x%lx\n%s\033[0m",
                       s.host.c_str(), s.kern.c_str(),
                       s.uph, s.nc,
                       s.taint, decode_taint(s.taint).c_str());
            } else if (c == "9") {
                im.detect();
                printf("\033[32mInit:%s Installed:%s\n"
                       "1)Install 2)Remove 3)Back\n>\033[0m",
                       im.name.c_str(), im.installed() ? "Y" : "N");
                std::string sc;
                std::getline(std::cin, sc);
                if (sc == "1") {
                    if (geteuid() != 0) {
                        printf("Need root\n");
                        continue;
                    }
                    im.install();
                    printf("%s", im.out.c_str());
                } else if (sc == "2") {
                    if (geteuid() != 0) {
                        printf("Need root\n");
                        continue;
                    }
                    im.uninstall();
                    printf("%s", im.out.c_str());
                }
            }
        }
        curl_global_cleanup();
    }
};

/* ═══════════════════════════════════════════════════════
 * DAEMON MODE
 * ═══════════════════════════════════════════════════════ */
class DaemonApp {
public:
    void run() {
        {
            std::ofstream pf(Cfg::PIDFILE);
            if (pf) pf << getpid();
        }
        g_log.open();
        g_log.log("INFO", "Daemon v" + std::string(Cfg::VER));

        Collector col;
        Auditor aud;
        aud.init();
        time_t last_report = time(nullptr);

        while (g_run) {
            col.tick();
            aud.scan();
            auto& s = col.st;
            int al = aud.alerts.load();

            if (s.rpct >= Cfg::MEM_CRIT) {
                g_log.log("CRIT", "Mem " + std::to_string((int)s.rpct) + "%");
            } else if (s.rpct >= Cfg::MEM_WARN) {
                g_log.log("WARN", "Mem " + std::to_string((int)s.rpct) + "%");
            }

            float lw = s.nc * Cfg::LOAD_WARN;
            float lc = s.nc * Cfg::LOAD_CRIT;
            if (s.la1 >= lc) {
                g_log.log("CRIT", "Load " + std::to_string(s.la1));
            } else if (s.la1 >= lw) {
                g_log.log("WARN", "Load " + std::to_string(s.la1));
            }

            for (auto& [n, t] : s.temps) {
                if (t >= Cfg::TEMP_CRIT) {
                    g_log.log("CRIT",
                              "Temp " + n + ":" + std::to_string((int)t));
                } else if (t >= Cfg::TEMP_WARN) {
                    g_log.log("WARN",
                              "Temp " + n + ":" + std::to_string((int)t));
                }
            }

            time_t now = time(nullptr);
            if ((now - last_report) >= Cfg::RPT_SEC || g_rpt) {
                g_rpt = false;
                g_log.log("INFO",
                    "RPT cpu:" + std::to_string((int)s.cpu) +
                    " ram:" + std::to_string((int)s.rpct) +
                    " ld:" + std::to_string(s.la1) +
                    " al:" + std::to_string(al) +
                    " t:0x" + std::to_string(s.taint));
                last_report = now;
            }

            for (int i = 0; i < Cfg::SCAN_SEC * 10 && g_run; i++) {
                std::this_thread::sleep_for(100ms);
            }
        }

        g_log.log("INFO", "Stop");
        g_log.close();
        unlink(Cfg::PIDFILE);
    }
};

/* ═══════════════════════════════════════════════════════
 * ONE-SHOT REPORT
 * ═══════════════════════════════════════════════════════ */
static void report() {
    Collector col;
    Auditor aud;
    aud.init();
    col.tick();
    std::this_thread::sleep_for(1s);
    col.tick();
    aud.scan();
    auto& s = col.st;

    printf("\033[32m=== HEALTH REPORT ===\033[0m\n");
    printf("Host:%s Kern:%s Up:%.1fh CPUs:%d\n",
           s.host.c_str(), s.kern.c_str(), s.uph, s.nc);
    printf("CPU:%.1f%% RAM:%lld/%lldMB(%.1f%%) Disk:%.1f%%\n",
           s.cpu, (long long)s.ruse, (long long)s.rtot, s.rpct, s.dpct);
    printf("Load:%.2f %.2f %.2f P:%d\n", s.la1, s.la5, s.la15, s.procs);
    if (s.gpuok) {
        printf("GPU:%s %.1f%% T:%.0fC\n",
               s.gpuname.c_str(), s.gpct, s.gtmp);
    }
    printf("Taint:0x%lx\n%s", s.taint, decode_taint(s.taint).c_str());
    printf("PSI cpu:%.1f%% mem:%.1f%%(f:%.1f%%) io:%.1f%%\n",
           s.pcpu, s.pmem, s.pmemf, s.pio);
    if (!s.temps.empty()) {
        printf("Temps:\n");
        for (auto& [n, t] : s.temps) {
            printf("  %-30s %.0fC\n", n.c_str(), t);
        }
    }
    printf("Alerts:%d\n", aud.alerts.load());
    {
        std::lock_guard<std::mutex> lk(aud.mtx);
        int n = 0;
        for (auto& e : aud.logs) {
            printf("  [%s][%s] %s\n",
                   sev_tag(e.sev), e.sub.c_str(),
                   e.msg.substr(0, 100).c_str());
            if (++n >= 20) break;
        }
    }
}

/* ═══════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════ */
int main(int argc, char* argv[]) {
    signal(SIGTERM, on_sig);
    signal(SIGINT,  on_sig);
    signal(SIGHUP,  on_sig);
    signal(SIGUSR1, on_sig);
    signal(SIGPIPE, SIG_IGN);

    enum { M_TUI, M_CON, M_DAE, M_INST, M_UNINST, M_STAT, M_RPT, M_HELP };
    int mode = M_TUI;

    for (int i = 1; i < argc; i++) {
        std::string a(argv[i]);
        if (a == "--console" || a == "-c")   mode = M_CON;
        else if (a == "--daemon" || a == "-d")   mode = M_DAE;
        else if (a == "--install")               mode = M_INST;
        else if (a == "--uninstall")             mode = M_UNINST;
        else if (a == "--status")                mode = M_STAT;
        else if (a == "--report" || a == "-r")   mode = M_RPT;
        else if (a == "--help" || a == "-h")     mode = M_HELP;
    }

    switch (mode) {
        case M_HELP:
            printf("Cyber-Watchdog v%s\n"
                   "  (none)       TUI (ncurses)\n"
                   "  -c           Console\n"
                   "  -d           Daemon\n"
                   "  -r           Report\n"
                   "  --install    Install service\n"
                   "  --uninstall  Remove service\n"
                   "  --status     Show status\n"
                   "Keys: 1-7 tabs, S scan, A ai, F filter, j/k scroll, Q quit\n"
                   "Signals: HUP=reload USR1=report TERM=stop\n",
                   Cfg::VER);
            return 0;

        case M_INST:
            if (geteuid() != 0) {
                fprintf(stderr, "sudo %s --install\n", argv[0]);
                return 1;
            }
            {
                InitMgr im;
                im.install();
                printf("%s", im.out.c_str());
            }
            return 0;

        case M_UNINST:
            if (geteuid() != 0) {
                fprintf(stderr, "Need root\n");
                return 1;
            }
            {
                InitMgr im;
                im.uninstall();
                printf("%s", im.out.c_str());
            }
            return 0;

        case M_STAT:
            {
                InitMgr im;
                im.detect();
                printf("v%s init:%s inst:%s st:%s\n",
                       Cfg::VER, im.name.c_str(),
                       im.installed() ? "Y" : "N",
                       im.status().c_str());
            }
            return 0;

        case M_RPT:
            report();
            return 0;

        case M_DAE:
            {
                DaemonApp d;
                d.run();
            }
            return 0;

        case M_CON:
            {
                ConsoleApp c;
                c.run();
            }
            return 0;

        default:
            if (!isatty(STDOUT_FILENO)) {
                fprintf(stderr, "Use -c or -d\n");
                return 1;
            }
            {
                TUIApp app;
                app.run();
            }
            return 0;
    }
}
CPPEOF
