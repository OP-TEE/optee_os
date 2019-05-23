cppflags-y += -I$(sub-dir)/../..

srcs-$(CFG_ARM32_$(sm)) += utee_syscalls_a32.S
srcs-$(CFG_ARM64_$(sm)) += utee_syscalls_a64.S
srcs-$(CFG_ARM32_$(sm)) += utee_mcount_a32.S
srcs-$(CFG_ARM64_$(sm)) += utee_mcount_a64.S

ifneq ($(sm),ldelf)
srcs-y += user_ta_entry.c
srcs-y += utee_misc.c
subdirs-y += gprof
subdirs-y += ftrace
endif #$(sm-$(sm)-is-ld)

