#!/bin/bash
check() { return 0; }
install() { inst_binary /usr/local/sbin/cyber-watchdog; inst_hook pre-pivot 00 "$moddir/start-watchdog.sh"; }
