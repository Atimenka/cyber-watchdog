all: heartbeat
heartbeat: heartbeat.asm
	@nasm -f elf64 $< -o heartbeat.o 2>/dev/null && ld heartbeat.o -o $@ 2>/dev/null && echo "[OK] heartbeat" || echo "[SKIP] nasm N/A"
clean:
	rm -f heartbeat heartbeat.o
.PHONY: all clean
