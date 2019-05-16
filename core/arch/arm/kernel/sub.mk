ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += user_ta.c
srcs-$(CFG_REE_FS_TA) += ree_fs_ta.c
srcs-$(CFG_EARLY_TA) += early_ta.c
srcs-$(CFG_SECSTOR_TA) += secstor_ta.c
endif
srcs-y += pseudo_ta.c
srcs-y += elf_load.c
srcs-$(CFG_TA_DYNLINK) += elf_load_dyn.c
srcs-y += tee_time.c
srcs-y += otp_stubs.c
srcs-y += delay.c

srcs-$(CFG_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(CFG_SECURE_TIME_SOURCE_REE) += tee_time_ree.c
srcs-$(CFG_ARM64_core) += timer_a64.c

srcs-$(CFG_ARM32_core) += proc_a32.S
srcs-$(CFG_ARM32_core) += spin_lock_a32.S
srcs-$(CFG_ARM64_core) += proc_a64.S
srcs-$(CFG_ARM64_core) += spin_lock_a64.S
srcs-$(CFG_TEE_CORE_DEBUG) += spin_lock_debug.c
srcs-$(CFG_ARM32_core) += tlb_helpers_a32.S
srcs-$(CFG_ARM64_core) += tlb_helpers_a64.S
srcs-$(CFG_ARM64_core) += cache_helpers_a64.S
srcs-$(CFG_ARM32_core) += cache_helpers_a32.S
srcs-$(CFG_PL310) += tz_ssvce_pl310_a32.S
srcs-$(CFG_PL310) += tee_l2cc_mutex.c

srcs-$(CFG_ARM32_core) += thread_a32.S
srcs-$(CFG_ARM64_core) += thread_a64.S
srcs-y += thread.c
srcs-y += abort.c
srcs-$(CFG_WITH_VFP) += vfp.c
ifeq ($(CFG_WITH_VFP),y)
srcs-$(CFG_ARM32_core) += vfp_a32.S
srcs-$(CFG_ARM64_core) += vfp_a64.S
endif
srcs-y += trace_ext.c
srcs-$(CFG_ARM32_core) += misc_a32.S
srcs-$(CFG_ARM64_core) += misc_a64.S
srcs-y += mutex.c
srcs-$(CFG_LOCKDEP) += mutex_lockdep.c
srcs-y += wait_queue.c
srcs-$(CFG_PM_STUBS) += pm_stubs.c
cflags-pm_stubs.c-y += -Wno-suggest-attribute=noreturn

srcs-$(CFG_GENERIC_BOOT) += generic_boot.c
ifeq ($(CFG_GENERIC_BOOT),y)
srcs-$(CFG_ARM32_core) += generic_entry_a32.S
srcs-$(CFG_ARM64_core) += generic_entry_a64.S
ifeq ($(CFG_TEE_CORE_PIE),y)
aflags-remove-generic_entry_a32.S-$(CFG_ARM32_core) = -fpic
aflags-remove-generic_entry_a64.S-$(CFG_ARM64_core) = -fpic
endif
endif

ifeq ($(CFG_UNWIND),y)
srcs-y += unwind_arm32.c
srcs-$(CFG_ARM64_core) += unwind_arm64.c
endif

srcs-$(CFG_VIRTUALIZATION) += virtualization.c

srcs-y += link_dummies.c

asm-defines-y += asm-defines.c
