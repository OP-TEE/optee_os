cppflags-y += -I$(sub-dir)/../../..

ifneq ($(sm),ldelf) # TA, core
srcs-$(CFG_TA_FTRACE_SUPPORT) += ftrace.c
endif
