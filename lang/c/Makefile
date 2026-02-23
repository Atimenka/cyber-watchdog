all: panic_logger
panic_logger: panic_logger.c
	$(CC) -O2 -Wall -static -o $@ $<
clean:
	rm -f panic_logger
.PHONY: all clean
