cppflags-y += -I$(sub-dir)/../..

srcs-y += user_ta_entry.c
srcs-y += utee_misc.c
srcs-$(CFG_ARM32_$(sm)) += utee_syscalls_a32.S
srcs-$(CFG_ARM64_$(sm)) += utee_syscalls_a64.S

subdirs-$(CFG_TA_GPROF_SUPPORT) += gprof
