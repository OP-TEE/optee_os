srcs-y += tee_entry.c
srcs-$(CFG_COMMON_INIT) += init.c
ifeq ($(CFG_COMMON_INIT),y)
srcs-$(CFG_ARM32_core) += entry_a32.S
endif
srcs-$(CFG_COMMON_BOOTCFG) += core_bootcfg.c
