# SPDX-License-Identifier: GPL-2.0-only
# Linux 7.3's r8152 (the first releases with the RTL8159, USB 0bda:815a) built for an older
# running kernel, whose own r8152 leaves the adapter to cdc_ncm (MTU 1504, no jumbo frames).
#
#   make                 # r8152.ko for the running kernel (needs its linux-headers); not as root
#   sudo make install    # into /lib/modules/KVER/updates/, which takes precedence over the kernel's own
#   sudo make uninstall
#
# KVER=... builds for another installed kernel (repeat after a kernel update), or let DKMS do it:
#
#   sudo make dkms-install     # the source into /usr/src, built and installed for the running kernel,
#                              # and again by itself for every kernel installed later (needs dkms)
#   sudo make dkms-uninstall
#
# r8152.c is drivers/net/usb/r8152.c of Linux v7.3, unmodified
# (sha256 9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f). It asks for
# rtl_nic/rtl8159-1.fw (the PHY patch), which linux-firmware does not carry; without it the
# driver still binds, and the link is reported to come up at 5 Gbit/s instead of 10.

KVER ?= $(shell uname -r)
MODDIR := /lib/modules/$(KVER)
KDIR ?= $(MODDIR)/build
DEST := $(MODDIR)/updates/r8152.ko

.PHONY: all install uninstall clean dkms-install dkms-uninstall

DKMS_NAME := r8152-rtl8159
DKMS_VERSION := 7.3
DKMS_SRC := /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

install:
	@test -f r8152.ko || { echo "build first: make (not as root)" >&2; exit 1; }
	install -D -m 0644 r8152.ko $(DEST)
	depmod -a $(KVER)

uninstall:
	rm -f $(DEST)
	depmod -a $(KVER)

# The driver kept current by DKMS: its own copy of the source, built for the running kernel now and for
# each kernel the host installs afterwards.
#
# The copy `make install` put in updates/ goes first, and only once DKMS has built its own: DKMS
# declines to install beside a module that is the same as its own ("already installed (unversioned
# module)") and still ends without a fault, which would leave the host with the kernel's own driver.
# The kernel's own r8152 is set aside by DKMS itself, which puts it back at dkms-uninstall. The last
# line is the check that the driver is where the next start will take it from.
dkms-install:
	@command -v dkms > /dev/null || { echo "dkms is not installed: sudo apt install dkms" >&2; exit 1; }
	@if dkms status $(DKMS_NAME)/$(DKMS_VERSION) | grep -q .; then dkms remove $(DKMS_NAME)/$(DKMS_VERSION) --all; fi
	install -d $(DKMS_SRC)
	install -m 0644 r8152.c Kbuild dkms.conf $(DKMS_SRC)/
	dkms add $(DKMS_NAME)/$(DKMS_VERSION)
	dkms build $(DKMS_NAME)/$(DKMS_VERSION) -k $(KVER)
	rm -f $(DEST)
	dkms install $(DKMS_NAME)/$(DKMS_VERSION) -k $(KVER)
	@ls $(MODDIR)/updates/dkms/r8152.ko* > /dev/null 2>&1 || { echo "DKMS did not install the driver for $(KVER): dkms status" >&2; exit 1; }

dkms-uninstall:
	-dkms remove $(DKMS_NAME)/$(DKMS_VERSION) --all
	rm -rf $(DKMS_SRC)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
