# Plugins
API: plugins/api/plugin_api.h
Build: gcc -shared -fPIC -O2 -o p.so p.c -I plugins/api/
Exports: cw_plugin_info, cw_plugin_init, cw_plugin_tick, cw_plugin_alert, cw_plugin_cleanup
