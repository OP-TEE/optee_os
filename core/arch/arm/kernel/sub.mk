srcs-y += tee_ta_manager.c
srcs-y += tee_time.c

srcs-$(CFG_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(CFG_SECURE_TIME_SOURCE_RTT) += tee_time_rtt.c
srcs-$(CFG_SECURE_TIME_SOURCE_REE) += tee_time_ree.c

srcs-y += tee_time_unpg.c
srcs-$(CFG_ARM32_core) += proc_a32.S
srcs-$(CFG_ARM32_core) += ssvce_a32.S
srcs-$(CFG_PL310) += tz_ssvce_pl310_a32.S
srcs-$(CFG_PL310) += tee_l2cc_mutex.c

srcs-$(CFG_ARM32_core) += thread_a32.S
srcs-y += thread.c
srcs-$(CFG_WITH_VFP) += vfp.c
srcs-$(CFG_WITH_VFP) += vfp_a32.S
srcs-y += trace_ext.c
srcs-$(CFG_ARM32_core) += misc_a32.S
srcs-y += mutex.c
