# Cyber-Watchdog
Super-Early Kernel Health Monitor
**C++20 | C | x86_64 ASM | Rust | Bash**

## Boot Chain

    initramfs (dracut/mkinitcpio/initramfs-tools)
    initrd.target (systemd initrd)
    sysinit.target (before basic.target)
    SysVinit S01 / OpenRC sysinit
    multi-user.target

text


## Usage

sudo cyber-watchdog # TUI
sudo cyber-watchdog -c # Console
sudo cyber-watchdog -r # Report
sudo cyber-watchdog --status

text

Keys: 1-9 tabs S scan A ai N net P panic F filter Q quit

## Plugins

cw-plugin-mgr list
cw-plugin-mgr enable cpu-alert

text

License: GPLv3
