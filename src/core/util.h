#pragma once
#include <string>
#include <array>
#include <fstream>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <climits>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

inline std::string xcmd(const std::string& c) {
    std::array<char,4096> b{}; std::string o;
    FILE* p = popen(c.c_str(),"r"); if (!p) return "";
    while (fgets(b.data(),(int)b.size(),p)) o += b.data();
    pclose(p); return o;
}
inline int xrc(const std::string& c) { return WEXITSTATUS(system(c.c_str())); }
inline std::string T(const std::string& s) {
    auto a = s.find_first_not_of(" \t\n\r");
    if (a == std::string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t\n\r") - a + 1);
}
inline std::string rl(const std::string& p) { std::ifstream f(p); if (!f) return ""; std::string l; std::getline(f,l); return T(l); }
inline std::string ra(const std::string& p) { std::ifstream f(p); if (!f) return ""; return {std::istreambuf_iterator<char>(f),{}}; }
inline std::string tnow() { auto t=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); char b[64]; std::strftime(b,sizeof(b),"%Y-%m-%d %H:%M:%S",std::localtime(&t)); return b; }
inline std::string tshort() { auto t=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); char b[32]; std::strftime(b,sizeof(b),"%H:%M:%S",std::localtime(&t)); return b; }
inline int ncpu() { int n=sysconf(_SC_NPROCESSORS_ONLN); return n>0?n:1; }
inline std::string selfp() { char b[PATH_MAX]; ssize_t n=readlink("/proc/self/exe",b,sizeof(b)-1); if(n<=0)return""; b[n]=0; return b; }

namespace FS {
    inline bool ex(const std::string& p) { struct stat s; return stat(p.c_str(),&s)==0; }
    inline bool isd(const std::string& p) { struct stat s; return stat(p.c_str(),&s)==0 && S_ISDIR(s.st_mode); }
    inline void mkd(const std::string& p) { xrc("mkdir -p '"+p+"' 2>/dev/null"); }
}

inline size_t cwcb(void* p, size_t s, size_t n, void* u) { ((std::string*)u)->append((char*)p,s*n); return s*n; }

namespace JS {
    inline std::string esc(const std::string& s) {
        std::string o; o.reserve(s.size()+32);
        for (char c:s) switch(c) {
            case '"': o+="\\\""; break; case '\\': o+="\\\\"; break;
            case '\n': o+="\\n"; break; case '\r': o+="\\r"; break;
            case '\t': o+="\\t"; break;
            default: if((unsigned char)c<0x20){char b[8];snprintf(b,8,"\\u%04x",(unsigned char)c);o+=b;}else o+=c;
        } return o;
    }
    inline std::string get(const std::string& j, const std::string& k) {
        auto p=j.find("\""+k+"\""); if(p==std::string::npos)return"";
        p=j.find(':',p); if(p==std::string::npos)return"";
        p=j.find('"',p+1); if(p==std::string::npos)return""; p++;
        std::string r;
        while(p<j.size()&&j[p]!='"') {
            if(j[p]=='\\'&&p+1<j.size()){p++;switch(j[p]){case'n':r+='\n';break;case'"':r+='"';break;case'\\':r+='\\';break;case't':r+='\t';break;default:r+=j[p];}}
            else r+=j[p]; p++;
        } return r;
    }
}
