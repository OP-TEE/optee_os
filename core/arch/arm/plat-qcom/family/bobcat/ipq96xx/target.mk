$(call force,CFG_TEE_CORE_NB_CORE,5)
$(call force,CFG_CORE_CLUSTER_SHIFT,3)
CFG_NUM_THREADS ?= 5

$(call force,CFG_EMBED_DTB,y)
CFG_EMBED_DTB_SOURCE_FILE ?= qcom/ipq9650-rdp488.dts

$(call force,CFG_ARM_GICV3,y)

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

CFG_TZDRAM_START ?= 0x8A680000
# The embedded DT puts the TME-Lite IPC carveout in the last part of the
# memory OP-TEE is given, so TZDRAM ends before it
CFG_TZDRAM_SIZE ?= (0x280000 - $(CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE))
CFG_TEE_RAM_VA_SIZE ?= $(CFG_TZDRAM_SIZE)

CFG_QCOM_PAS_PTA ?= y

CFG_PAS_MD_SLOTS := 2
CFG_PAS_TA_HEAP_SIZE := (16 * 1024)

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
$(call force,CFG_QCOM_PAS_AUTH,n)
endif

CFG_HWRNG_PTA ?= y
ifeq ($(CFG_HWRNG_PTA),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
$(call force,CFG_QCOM_TMEL_RNG,y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_RNG)
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_RATE ?= 0
endif
