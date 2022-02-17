cppflags-y += -I$(sub-dir)/../..

srcs-y += utee_syscalls_rv.S

ifneq ($(sm),ldelf)
srcs-y += tcb.c
srcs-y += user_ta_entry.c
subdirs-y += gprof
endif #$(sm-$(sm)-is-ld)
