# Equal to RAMBLUR_PIMEM_VAULT_TA_SIZE: TA RAM is the RAMBLUR TA window
CFG_TA_RAM_VA_SIZE ?= 0x1a00000

CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
# PAS subsystems map their controller windows at runtime from the reserved VA
# pool (never released), in 2 MiB blocks: 84 MiB for the DSP and iris windows.
CFG_RESERVED_VASPACE_SIZE ?= (96 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
