subdirs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += tests

srcs-$(CFG_ATTESTATION_PTA) += attestation.c
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
srcs-$(CFG_WIDEVINE_PTA) += widevine.c

subdirs-y += bcm
subdirs-y += stm32mp
subdirs-y += imx
subdirs-y += k3

ifeq ($(CFG_REMOTEPROC_PTA),y)
gensrcs-y += rproc_pub_key
produce-rproc_pub_key = rproc_pub_key.c
depends-rproc_pub_key = $(RPROC_SIGN_KEY) scripts/pem_to_pub_c.py
recipe-rproc_pub_key = $(PYTHON3) scripts/pem_to_pub_c.py \
	--prefix rproc_pub_key --key $(RPROC_SIGN_KEY)    \
	--out $(sub-dir-out)/rproc_pub_key.c
endif