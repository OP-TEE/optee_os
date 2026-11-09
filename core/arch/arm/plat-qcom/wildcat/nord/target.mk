# Nord (SA8797P / Oryon) OP-TEE platform.

# Threads are expensive in OP-TEE, so they don't have
# to be same as number of cores.
$(call force,CFG_TEE_CORE_NB_CORE,18)

# DARE-TZ secure memory regions. DARE is another in-line
# memory encryption IP similar to pIMEM but on wildcat arch
# it is setup by TME root-of-trust, no specific driver needed
# in OP-TEE for that.
CFG_TZDRAM_START ?= 0xBC600000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x07800000

CFG_QCOM_RPMH_CLIENT ?= y
ifeq ($(CFG_QCOM_RPMH_CLIENT),y)
$(call force,CFG_QCOM_CMD_DB,y)
endif

# Fuse provisioning: off by default. When enabled it uses the security
# processor and the flat data format. It also needs CFG_CORE_EL3_SPMC=y and
# CFG_QCOM_PROVISION_BUFFER_AUTHENTICATED=y once the data window is confirmed
# to be secure and authenticated, see target_config.h.
CFG_QCOM_QFPROM_FUSEPROV ?= n
ifeq ($(CFG_QCOM_QFPROM_FUSEPROV),y)
CFG_QCOM_PROVISION_BACKEND ?= tme
CFG_QCOM_PROVISION_SEC_ELF_V3 ?= y
endif
