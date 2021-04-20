srcs-$(CFG_CORE_SANITIZE_KADDRESS) += asan.c
cflags-remove-asan.c-y += $(cflags_kasan)
srcs-y += assert.c
srcs-y += console.c
srcs-$(CFG_DT) += dt.c
srcs-$(CFG_DT) += dt_driver.c
srcs-y += pm.c
srcs-y += handle.c
srcs-y += interrupt.c
srcs-$(CFG_WITH_USER_TA) += ldelf_syscalls.c
srcs-$(CFG_LOCKDEP) += lockdep.c
ifneq ($(CFG_CORE_FFA),y)
srcs-$(CFG_CORE_DYN_SHM) += msg_param.c
endif
srcs-y += panic.c
srcs-y += refcount.c
srcs-y += tee_misc.c
srcs-y += tee_ta_manager.c
srcs-y += ts_manager.c
srcs-$(CFG_CORE_SANITIZE_UNDEFINED) += ubsan.c
srcs-y += scattered_array.c
srcs-y += huk_subkey.c
srcs-$(CFG_SHOW_CONF_ON_BOOT) += show_conf.c
srcs-y += user_mode_ctx.c
srcs-$(CFG_CORE_TPM_EVENT_LOG) += tpm.c
srcs-y += initcall.c
srcs-$(CFG_WITH_USER_TA) += user_access.c
srcs-y += mutex.c
srcs-$(CFG_LOCKDEP) += mutex_lockdep.c
srcs-y += wait_queue.c
srcs-y += notif.c

ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += user_ta.c
srcs-$(CFG_REE_FS_TA) += ree_fs_ta.c
srcs-$(CFG_EARLY_TA) += early_ta.c
srcs-$(CFG_SECSTOR_TA) += secstor_ta.c
endif

srcs-$(CFG_EMBEDDED_TS) += embedded_ts.c
srcs-y += pseudo_ta.c
