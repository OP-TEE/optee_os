cppflags-y += -I$(sub-dir)/../..

srcs-$(CFG_ARM32_$(sm)) += utee_syscalls_a32.S
srcs-$(CFG_ARM64_$(sm)) += utee_syscalls_a64.S

ifneq ($(sm),ldelf)
srcs-y += tcb.c
srcs-y += user_ta_entry.c
subdirs-y += gprof
endif #$(sm-$(sm)-is-ld)

