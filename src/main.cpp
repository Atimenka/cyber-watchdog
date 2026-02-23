#include "core/types.h"
#include "core/util.h"
#include "core/log.h"
#include <iostream>
#include <fstream>
#include <csignal>

std::atomic<bool> g_run{true}, g_rpt{false};
FLog g_log;

static void on_sig(int s) { if(s==SIGTERM||s==SIGINT)g_run=false; if(s==SIGUSR1)g_rpt=true; }

static void report() {
    printf("=== Cyber-Watchdog %s ===\n",C::VER);
    printf("Host: %s\nKernel: %s\nCPUs: %d\n",rl("/proc/sys/kernel/hostname").c_str(),rl("/proc/sys/kernel/osrelease").c_str(),ncpu());
    printf("Load: %s\n",rl("/proc/loadavg").c_str());
    printf("Mem:\n%s\n",T(xcmd("free -m|grep -E 'Mem|Swap'")).c_str());
    printf("Disk:\n%s\n",T(xcmd("df -h /|tail -1")).c_str());
    unsigned long taint=0; auto ts=rl("/proc/sys/kernel/tainted");
    if(!ts.empty()) try{taint=std::stoul(ts);}catch(...){}
    printf("Taint: 0x%lx\n%s",taint,decode_taint(taint).c_str());
    auto e=xcmd("dmesg --level=err,crit,alert,emerg 2>/dev/null|tail -5");
    printf(e.empty()?"\nNo errors.\n":"\nErrors:\n%s",e.c_str());
}

static void panic_save() {
    auto dmesg=xcmd("dmesg -T 2>/dev/null||dmesg"); if(dmesg.empty()){puts("Empty dmesg");return;}
    int saved=0; const char* d[]={"/","/boot","/home","/tmp","/root","/var/log",nullptr};
    for(int i=0;d[i];i++){if(!FS::isd(d[i]))continue;
        std::string fp=std::string(d[i])+"/cyber-watchdog-panic.log";
        std::ofstream out(fp,std::ios::app);
        if(out){out<<"\n=== PANIC "<<tnow()<<" ===\n"<<dmesg<<"\n=== END ===\n";out.flush();saved++;printf("  %s\n",fp.c_str());}
    } printf("Saved to %d locations\n",saved);
}

int main(int argc, char* argv[]) {
    signal(SIGTERM,on_sig); signal(SIGINT,on_sig); signal(SIGPIPE,SIG_IGN);
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="-h"||a=="--help"){printf("Cyber-Watchdog %s\n -r Report\n -c Console\n -d Daemon\n --status\n --panic-save\n --net-up\n --install (use install.sh)\n",C::VER);return 0;}
        if(a=="-r"||a=="--report"){report();return 0;}
        if(a=="--status"){auto p=rl(C::PIDF);printf("cyber-watchdog: %s\n",(!p.empty()&&FS::ex("/proc/"+p))?"running":"stopped");
            auto s=T(xcmd("systemctl is-active cyber-watchdog 2>/dev/null"));if(!s.empty())printf("systemd: %s\n",s.c_str());return 0;}
        if(a=="--panic-save"){panic_save();return 0;}
        if(a=="--net-up"){xrc("ip link set eth0 up 2>/dev/null");xrc("dhclient -1 -q eth0 2>/dev/null||dhcpcd -1 -q eth0 2>/dev/null");
            printf("Network: %s\n",xrc("ping -c1 -W3 8.8.8.8>/dev/null 2>&1")==0?"UP":"FAILED");return 0;}
        if(a=="-d"||a=="--daemon"){g_log.open();g_log.log("INFO","started");while(g_run)sleep(C::SCAN_S);g_log.log("INFO","stopped");g_log.close();return 0;}
        if(a=="-c"||a=="--console"){report();return 0;}
        if(a=="--install"||a=="--uninstall"){puts("Use: sudo bash install.sh");return 0;}
    }
    printf("\033[32mCyber-Watchdog %s\033[0m\n\n -r report | --status | --panic-save | --net-up | -d daemon | -h help\n Full TUI: sudo bash install.sh\n",C::VER);
    return 0;
}
