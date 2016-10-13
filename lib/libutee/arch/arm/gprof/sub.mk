cppflags-y += -I$(sub-dir)/../../..

srcs-y += gprof.c
cflags-remove-gprof.c-y += -Wcast-align
srcs-$(CFG_ARM32_$(sm)) += gprof_a32.S
srcs-$(CFG_ARM64_$(sm)) += gprof_a64.S
