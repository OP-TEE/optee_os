srcs-y += tee_core_trace.c
srcs-y += tee_ta_manager.c
srcs-y += tee_time.c

srcs-$(WITH_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(WITH_SECURE_TIME_SOURCE_RTT) += tee_time_rtt.c
srcs-$(WITH_SECURE_TIME_SOURCE_REE) += tee_time_ree.c

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
