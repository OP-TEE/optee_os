$(call force,CFG_TEE_CORE_NB_CORE,5)
$(call force,CFG_CORE_CLUSTER_SHIFT,3)
CFG_NUM_THREADS ?= 5

$(call force,CFG_ARM_GICV3,y)

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

CFG_TZDRAM_START ?= 0x8A680000
CFG_TZDRAM_SIZE ?= 0x280000
# Reserve the TMEL IPC coherent carveout at the end of TZDRAM.
ifeq ($(CFG_QCOM_TMEL_COM),y)
CFG_TEE_RAM_VA_SIZE ?= (0x280000 - $(CFG_TMECOM_IPCBUF_CARVEOUT_SIZE))
else
CFG_TEE_RAM_VA_SIZE ?= 0x280000
endif

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
# Images are authenticated by TME-Lite, not by the PAS TA.
$(call force,CFG_QCOM_PAS_AUTH,n)
$(call force,CFG_QCOM_TMEL_AUTH,y,required by CFG_QCOM_PAS_PTA)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_AUTH)
endif

# Hardware RNG via the TME-Lite RNG service, which needs the TME-Lite COM
# stack.
CFG_HWRNG_PTA ?= y
ifeq ($(CFG_HWRNG_PTA),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
$(call force,CFG_QCOM_TMEL_RNG,y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_RNG)
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_RATE ?= 0
endif
