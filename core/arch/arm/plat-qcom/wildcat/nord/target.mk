# Nord (SA8797P / Oryon) OP-TEE platform.

# Threads are expensive in OP-TEE, so they don't have
# to be same as number of cores.
$(call force,CFG_TEE_CORE_NB_CORE,18)

# DARE-TZ secure memory regions. DARE is another in-line
# memory encryption IP similar to pIMEM but on wildcat arch
# it is setup by TME root-of-trust, no specific driver needed
# in OP-TEE for that.
CFG_TZDRAM_START ?= 0xBC280000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x07B80000

# QUPv3 serial-engine (bus) clock set-rate/DFS walker, consumed on-demand by a
# future TEE-side SPI/I2C driver. Set-rate votes CX/MX via RPMh, so pull
# cmd_db/RPMh client in whenever the walker is built.
CFG_QCOM_CLK_CFG ?= y
ifeq ($(CFG_QCOM_CLK_CFG),y)
$(call force,CFG_QCOM_CMD_DB,y)
$(call force,CFG_QCOM_RPMH_CLIENT,y)
endif

CFG_QCOM_RPMH_CLIENT ?= y
ifeq ($(CFG_QCOM_RPMH_CLIENT),y)
$(call force,CFG_QCOM_CMD_DB,y)
endif
