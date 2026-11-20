# SPDX-License-Identifier: MIT
# wifi-beacons: a C11 compiler and the maths library; it reads sample files (sdr-recv --out).
CC ?= cc
CFLAGS ?= -O2
WARNINGS ?= -Wall -Wextra -Werror
PREFIX ?= /usr/local
override CFLAGS += -std=c11 $(WARNINGS)
LDLIBS += -lm

.PHONY: all clean install
all: build/wifi-beacons

build/wifi-beacons: wifi-beacons.c | build
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

build:
	mkdir -p $@

install: build/wifi-beacons
	install -D -m 755 $< $(DESTDIR)$(PREFIX)/bin/wifi-beacons

clean:
	rm -rf build
