#ifndef CW_PLUGIN_API_H
#define CW_PLUGIN_API_H
#include <stdint.h>
#define CW_API_VERSION 1
enum CWS { CW_DBG=0,CW_INF=1,CW_NOT=2,CW_WRN=3,CW_ERR=4,CW_CRT=5,CW_EMG=6 };
typedef struct { const char *ts,*src,*sub,*msg; int sev; } CWAlert;
typedef struct { float cpu_pct,ram_pct,swap_pct,load1,load5,load15,gpu_pct,gpu_temp,disk_pct,rx_kbs,tx_kbs; int64_t ram_mb; int n_alerts; uint64_t taint; } CWStats;
typedef struct { const char *name,*version,*author,*description; int api_ver,priority; } CWPluginInfo;
typedef struct { void(*log)(int,const char*); void(*emit_alert)(const char*,int,const char*); const CWStats*(*get_stats)(void); } CWHost;
#endif
