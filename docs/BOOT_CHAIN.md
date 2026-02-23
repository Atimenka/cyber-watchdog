# Boot Chain
1. initramfs (dracut/mkinitcpio/initramfs-tools)
2. initrd.target (systemd initrd)
3. sysinit.target -> basic.target
4. SysVinit S01 / OpenRC sysinit
5. multi-user.target
