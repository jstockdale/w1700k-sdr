# SPDX-License-Identifier: MIT
# The kernel itself is built by build.py; this file builds what is compiled
# against it: the w1700k_sdr module and the static unit-side clients.
ROOT := $(abspath ../..)
OUT := $(ROOT)/platform/build/linux
CROSS_COMPILE ?= $(ROOT)/platform/build/buildroot/host/bin/aarch64-buildroot-linux-musl-
export PATH := $(ROOT)/platform/build/buildroot/host/bin:$(PATH)
.PHONY: kernel module reader
kernel:
	python3 build.py
# The SDR driver and its unit-side clients. KDIR is a configured, built kernel
# tree (default: this directory's build output).
KDIR ?= $(OUT)
SDR := $(ROOT)/kernel/w1700k_sdr
# Built the same way, but not clients of the driver: the reset button's service, the GPS
# receiver's power line, and the low-power radio's reset line.
UNIT_PROGRAMS := keyd:w1700k-key gps:w1700k-gps efr32:w1700k-efr32-line
# The release verifier: ours (release.c) on the WMS2 envelope and Monocypher,
# which are vendored as they came and are held to their own warnings.
SEAL := $(ROOT)/seal
SEAL_SOURCES := release.c wms2.c monocypher.c optional/monocypher-ed25519.c
SDR_CLIENTS := probe:mt7996-probe download:mt7996-download stream:mt7996-stream \
	ctl:mt7996-ctl ledd:w1700k-led
module:
	mkdir -p $(SDR)/build
	$(MAKE) -C $(KDIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) M=$(SDR) MO=$(SDR)/build modules
reader:
	mkdir -p $(SDR)/build
	set -e; for pair in $(SDR_CLIENTS) $(UNIT_PROGRAMS); do \
		$(CROSS_COMPILE)gcc -std=c11 -O2 -Wall -Wextra -Werror -static \
			-I$(ROOT)/include/uapi -I$(ROOT)/include $(SDR)/$${pair%%:*}.c -lpthread -lm \
			-o $(SDR)/build/$${pair##*:}; \
	done
	$(CROSS_COMPILE)gcc -std=c99 -D_POSIX_C_SOURCE=200809L -Os -Wall -Wextra -Werror -Wno-comment \
		-static -I$(SEAL) -I$(SEAL)/include $(addprefix $(SEAL)/,$(SEAL_SOURCES)) \
		-o $(SDR)/build/w1700k-release
