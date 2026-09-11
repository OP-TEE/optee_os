$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_NUM_THREADS ?= 4

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

CFG_TZDRAM_START ?= 0x87D80000
CFG_TZDRAM_SIZE ?= 0x280000
# Reserve the TMEL IPC coherent carveout at the end of TZDRAM.
ifeq ($(CFG_QCOM_TMEL_COM),y)
CFG_TEE_RAM_VA_SIZE ?= (0x280000 - $(CFG_TMECOM_IPCBUF_CARVEOUT_SIZE))
else
CFG_TEE_RAM_VA_SIZE ?= 0x280000
endif

$(call force,CFG_QCOM_CSRNG,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)

# CSRNG already provides hw_get_random_bytes() on this SoC, so the TME-Lite
# RNG client must stay off to avoid a duplicate definition.
$(call force,CFG_QCOM_TMEL_RNG,n,CFG_QCOM_CSRNG provides the hwrng)

CFG_HWRNG_PTA ?= y
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_RATE ?= 0
