#pragma once
#include <mutex>
#include <cstdio>
#include <string>
#include "types.h"
#include "util.h"

class FLog {
    std::mutex m_; FILE* fp_=nullptr;
public:
    void open() { FS::mkd(C::LOGDIR); fp_=fopen(C::LOGF,"a"); }
    void close() { if(fp_){fclose(fp_);fp_=nullptr;} }
    void log(const char* lv, const std::string& msg) {
        std::lock_guard<std::mutex> lk(m_); if(!fp_) return;
        fprintf(fp_,"%s [%s] %s\n",tnow().c_str(),lv,msg.c_str()); fflush(fp_);
        if(ftell(fp_)>50*1024*1024){fclose(fp_);rename(C::LOGF,(std::string(C::LOGF)+".old").c_str());fp_=fopen(C::LOGF,"a");}
    }
};
extern FLog g_log;
