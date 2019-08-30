cppflags-y += -I$(sub-dir)/../../..

ifeq ($(filter $(sm), core ldelf),) # TA
srcs-$(CFG_TA_FTRACE_SUPPORT) += ftrace.c
endif
