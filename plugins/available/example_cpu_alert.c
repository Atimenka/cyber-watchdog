#include "../api/plugin_api.h"
static const CWHost *h;
CWPluginInfo *cw_plugin_info(void) { static CWPluginInfo i={"cpu-alert","0.1","CW","High CPU",CW_API_VERSION,50}; return &i; }
int cw_plugin_init(const CWHost *host) { h=host; h->log(CW_INF,"[cpu-alert] loaded"); return 0; }
void cw_plugin_tick(const CWStats *s) { if(s->cpu_pct>95) h->emit_alert("CPU",CW_CRT,"CPU>95%"); }
void cw_plugin_alert(const CWAlert *a) { (void)a; }
void cw_plugin_cleanup(void) {}
