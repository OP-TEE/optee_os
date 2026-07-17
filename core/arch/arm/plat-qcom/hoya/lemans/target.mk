CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM_FUSEPROV ?= y
endif

ifeq ($(CFG_QCOM_QFPROM_FUSEPROV),y)
$(call force,CFG_QCOM_CMD_DB,y)
$(call force,CFG_QCOM_RPMH_CLIENT,y)
$(call force,CFG_QCOM_QFPROM,y)
endif

CFG_QCOM_PAS_PTA ?= y
ifeq ($(CFG_QCOM_PAS_PTA),y)
# Each PAS subsystem maps its controller window at runtime via
# core_mmu_add_mapping() in pas_platform_mem_setup(). These late mappings
# are carved from the reserved VA pool and never released, so it must hold
# all six DSP windows at once (sizes from the reference TZ HWIO layout):
#   CDSP0 48M + CDSP1 48M + LPASS 16.5M + GP-DSP0 16M + GP-DSP1 16M +
#   IRIS 2M + CDSP0 sec-channel 8K = ~146.5 MB. The 60 MB default only
#   fits a single DSP. Reserve 256 MB to cover them with headroom for
#   mapping alignment and other late mappings.
CFG_RESERVED_VASPACE_SIZE ?= (256 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe

# Authenticate each PIL firmware image on INIT_IMAGE: verify the per-segment
# hash table against the loaded firmware, and (on devices with secure-boot
# fuses blown) validate the image's certificate chain, signature and
# fuse-bound bindings before releasing the peripheral from reset.
CFG_QCOM_PAS_AUTH ?= y
endif
