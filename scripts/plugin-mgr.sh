#!/bin/bash
PD="/opt/cyber-watchdog/plugins"; AV="$PD/available"; EN="$PD/enabled"; API="/opt/cyber-watchdog/api"
case "${1:-help}" in
    list) echo "Available:"; ls "$AV" 2>/dev/null; echo "Enabled:"; ls "$EN" 2>/dev/null;;
    enable) [ -f "$AV/$2.so" ]||gcc -shared -fPIC -O2 -o "$AV/$2.so" "$AV/$2.c" -I"$API" 2>/dev/null; ln -sf "$AV/$2.so" "$EN/$2.so"; echo "Enabled: $2";;
    disable) rm -f "$EN/$2.so"; echo "Disabled: $2";;
    install) cp "$2" "$AV/"; echo "Installed";;
    remove) rm -f "$AV/$2"* "$EN/$2"*; echo "Removed";;
    *) echo "Usage: $0 {list|enable|disable|install|remove} [name]";;
esac
