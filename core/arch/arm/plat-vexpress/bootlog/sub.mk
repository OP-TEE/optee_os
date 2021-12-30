global-incdirs-y += .

ifeq ($(PLATFORM_FLAVOR_qemu_virt),y)
srcs-$(CFG_BOOT_LOG_PTA) += bootlog.c
endif
