srcs-y += rpc_io_i2c.c
srcs-y += idle.c

srcs-$(CFG_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
ifeq ($(CFG_CALLOUT),y)
srcs-$(CFG_ARM64_core) += generic_timer.c
endif
srcs-$(CFG_ARM64_core) += timer_a64.c

srcs-$(CFG_ARM32_core) += spin_lock_a32.S
srcs-$(CFG_ARM64_core) += spin_lock_a64.S
srcs-$(CFG_ARM32_core) += tlb_helpers_a32.S
srcs-$(CFG_ARM64_core) += tlb_helpers_a64.S
srcs-$(CFG_ARM64_core) += cache_helpers_a64.S
srcs-$(CFG_ARM32_core) += cache_helpers_a32.S
srcs-$(CFG_PL310) += tz_ssvce_pl310_a32.S
srcs-$(CFG_PL310) += tee_l2cc_mutex.c

srcs-$(CFG_ARM32_core) += thread_a32.S
srcs-$(CFG_ARM64_core) += thread_a64.S
srcs-y += thread.c
ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += arch_scall.c
srcs-$(CFG_ARM32_core) += arch_scall_a32.S
srcs-$(CFG_ARM64_core) += arch_scall_a64.S
endif
ifeq ($(CFG_CORE_FFA),y)
srcs-y += thread_spmc.c
cppflags-thread_spmc.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
srcs-$(CFG_ARM64_core) += thread_spmc_a64.S
else
srcs-y += thread_optee_smc.c
srcs-$(CFG_ARM32_core) += thread_optee_smc_a32.S
srcs-$(CFG_ARM64_core) += thread_optee_smc_a64.S
endif
srcs-y += abort.c
srcs-$(CFG_WITH_VFP) += vfp.c
ifeq ($(CFG_WITH_VFP),y)
srcs-$(CFG_ARM32_core) += vfp_a32.S
srcs-$(CFG_ARM64_core) += vfp_a64.S
endif
srcs-$(CFG_ARM32_core) += misc_a32.S
srcs-$(CFG_ARM64_core) += misc_a64.S
srcs-$(CFG_WITH_STMM_SP) += stmm_sp.c
srcs-$(CFG_SECURE_PARTITION) += secure_partition.c
srcs-$(CFG_SECURE_PARTITION) += spmc_sp_handler.c

srcs-y += boot.c
srcs-$(CFG_ARM32_core) += entry_a32.S
srcs-$(CFG_ARM64_core) += entry_a64.S

ifeq ($(CFG_UNWIND),y)
srcs-$(CFG_ARM32_core) += unwind_arm32.c
srcs-$(CFG_ARM64_core) += unwind_arm64.c
endif

srcs-$(CFG_NS_VIRTUALIZATION) += virtualization.c
ifeq ($(CFG_SEMIHOSTING),y)
srcs-$(CFG_ARM64_core) += semihosting_a64.S
endif

srcs-y += link_dummies_paged.c
srcs-y += link_dummies_init.c

asm-defines-y += asm-defines.c
# Reflect the following dependencies:
# asm-defines.c includes <kernel/thread.h>
#   <kernel/thread.h> includes <asm.h>
#     <asm.h> includes <generated/arm32_sysreg.h>
#                  and <generated/arm32_gicv3_sysreg.h> (optional)
asm-defines-asm-defines.c-deps += $(out-dir)/core/include/generated/arm32_sysreg.h
ifeq ($(CFG_ARM_GICV3),y)
asm-defines-asm-defines.c-deps += $(out-dir)/core/include/generated/arm32_gicv3_sysreg.h
endif

ifeq ($(CFG_SYSCALL_FTRACE),y)
# We would not like to profile thread.c file as it provide common APIs
# that are needed for ftrace framework to trace syscalls. So profiling
# this file could create an incorrect cyclic behaviour.
cflags-remove-thread.c-y += -pg
# Tracing abort dump files corrupts the stack trace. So exclude them
# from profiling.
cflags-remove-abort.c-y += -pg
ifeq ($(CFG_UNWIND),y)
cflags-remove-unwind_arm32.c-y += -pg
cflags-remove-unwind_arm64.c-$(CFG_ARM64_core) += -pg
endif
endif
