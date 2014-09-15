srcs-y += tee_core_trace.c
cflags-tee_core_trace.c-y += -Wno-format
cflags-tee_core_trace.c-y += -Wno-format-nonliteral -Wno-format-security

srcs-y += tee_ta_manager.c
cflags-tee_ta_manager.c-y += -Wno-declaration-after-statement -Wno-format
cflags-tee_ta_manager.c-y += -Wno-unused-parameter
cflags-tee_ta_manager.c-y += -Wno-format-nonliteral -Wno-format-security
cflags-tee_ta_manager.c-y += -fno-strict-aliasing


srcs-y += tee_sleep_services.c
cflags-tee_sleep_services.c-y += -Wno-unused-parameter

srcs-y += tee_time.c

srcs-$(WITH_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(WITH_SECURE_TIME_SOURCE_RTT) += tee_time_rtt.c
srcs-$(WITH_SECURE_TIME_SOURCE_REE) += tee_time_ree.c
cflags-tee_time.c-y += -Wno-unused-parameter
cflags-tee_time.c-y += -fno-strict-aliasing

srcs-y += chip_services.c

srcs-y += tee_misc.c
srcs-y += tee_time_unpg.c
srcs-y += tz_proc.S
srcs-y += tz_ssvce.S
srcs-$(WITH_PL310) += tz_ssvce_pl310.S
srcs-y += tee_l2cc_mutex.c

srcs-y += thread_asm.S
srcs-y += thread.c
srcs-y += misc.S
srcs-y += mutex.c
cflags-mutex.c-y += -fno-strict-aliasing
