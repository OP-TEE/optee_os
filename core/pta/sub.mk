subdirs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += tests

srcs-$(CFG_ATTESTATION_PTA) += attestation.c
srcs-$(CFG_TEE_BENCHMARK) += benchmark.c
srcs-$(CFG_DEVICE_ENUM_PTA) += device.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_SECSTOR_TA_MGMT_PTA) += secstor_ta_mgmt.c
endif
srcs-$(CFG_WITH_STATS) += stats.c
srcs-$(CFG_SYSTEM_PTA) += system.c
srcs-$(CFG_SCP03_PTA) += scp03.c
srcs-$(CFG_APDU_PTA) += apdu.c
srcs-$(CFG_SCMI_PTA) += scmi.c
srcs-$(CFG_HWRNG_PTA) += hwrng.c
srcs-$(CFG_RTC_PTA) += rtc.c

subdirs-y += bcm
