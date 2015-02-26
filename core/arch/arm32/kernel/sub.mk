srcs-y += tee_ta_manager.c
srcs-y += tee_time.c

srcs-$(CFG_SECURE_TIME_SOURCE_ARM_GENERIC_TIMER) += tee_time_arm_generic_timer.c
srcs-$(CFG_SECURE_TIME_SOURCE_RTT) += tee_time_rtt.c
srcs-$(CFG_SECURE_TIME_SOURCE_REE) += tee_time_ree.c

srcs-y += tee_time_unpg.c
srcs-y += tz_proc.S
srcs-y += tz_ssvce.S
srcs-$(CFG_WITH_PL310) += tz_ssvce_pl310.S
srcs-y += tee_l2cc_mutex.c

srcs-y += thread_asm.S
srcs-y += thread.c
srcs-$(CFG_WITH_VFP) += vfp.c
srcs-$(CFG_WITH_VFP) += vfp_asm.S
srcs-y += trace_ext.c
srcs-y += misc.S
srcs-y += mutex.c
