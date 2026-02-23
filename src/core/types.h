#pragma once
#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <atomic>

enum { S_DBG=0, S_INF=1, S_NOT=2, S_WRN=3, S_ERR=4, S_CRT=5, S_EMG=6 };

inline const char* stag(int s) {
    const char* t[] = {"DBG","INF","NOT","WRN","ERR","CRT","EMG"};
    return (s >= 0 && s <= 6) ? t[s] : "???";
}

namespace C {
    constexpr auto VER = "a0.0.2";
    constexpr auto SBIN = "/usr/local/sbin/cyber-watchdog";
    constexpr auto LOGDIR = "/var/log/cyber-watchdog";
    constexpr auto LOGF = "/var/log/cyber-watchdog/watchdog.log";
    constexpr auto PIDF = "/var/run/cyber-watchdog.pid";
    constexpr auto CONF = "/etc/cyber-watchdog/watchdog.conf";
    constexpr auto PLUGD = "/opt/cyber-watchdog/plugins/enabled";
    constexpr auto PANICDIR = "/opt/cyber-watchdog/panic-logs";
    constexpr auto API_URL = "https://openrouter.ai/api/v1/chat/completions";
    constexpr auto MODEL = "google/gemini-2.0-flash-001";
    constexpr int MAXLOG = 500, SCAN_S = 5, STAT_MS = 800, RPT_S = 3600;
    constexpr int MW = 85, MC = 95;
    constexpr float LW = 2.0f, LC = 5.0f, TW = 80.0f, TC = 95.0f;
}

struct LogE { std::string ts, src, sub, msg, raw; int sev = S_INF; };

struct Stats {
    float cpu = 0; std::vector<float> cores;
    float rpct = 0; int64_t rtot = 0, ruse = 0, ravl = 0;
    float spct = 0; int64_t stot = 0, suse = 0, cache = 0, slb = 0;
    bool gpuok = false; std::string gpuname;
    float gpct = 0, gmem = 0, gtmp = 0, dpct = 0, rxk = 0, txk = 0;
    std::string kern, host;
    float uph = 0, la1 = 0, la5 = 0, la15 = 0;
    int procs = 0, nc = 1; unsigned long taint = 0;
    float pcpu = 0, pmem = 0, pmemf = 0, pio = 0;
    std::vector<std::pair<std::string, float>> temps;
};

struct Graphs {
    std::deque<float> cpu, ram, gpu, rx, tx, ld;
    void add(std::deque<float>& q, float v) { q.push_back(v); while ((int)q.size() > 120) q.pop_front(); }
};

struct NetI { std::string name, ip, mac, state; };
struct MntI { std::string mp, fs; float pct = 0; int64_t tot = 0, used = 0; };

inline const char* taint_bits[] = {
    "Proprietary(P)","ForceLoad(F)","SMP(S)","ForceUnload(R)","MCE(M)","BadPage(B)",
    "UserTaint(U)","OOPS(D)","ACPI(A)","Warning(W)","Staging(C)","Workaround(I)",
    "ExtMod(O)","Unsigned(E)","SoftLockup(L)","LivePatch(K)","Aux(X)","Randstruct(T)",nullptr
};

inline std::string decode_taint(unsigned long t) {
    if (!t) return "  (clean)"; std::string o;
    for (int i = 0; taint_bits[i] && i < 18; i++)
        if (t & (1UL << i)) o += "  [" + std::to_string(i) + "] " + taint_bits[i] + "\n";
    return o;
}

extern std::atomic<bool> g_run, g_rpt;
