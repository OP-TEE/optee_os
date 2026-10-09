$(call force,CFG_QCOM_RAMBLUR_PIMEM_V2,y,Talos has RAMBLUR v2.3)

# The TZ Apps region of the QCS615 memory map backs RAMBLUR window 2
CFG_TA_RAM_VA_SIZE ?= 0x1c00000

$(call force,CFG_EMBED_DTB,y)
CFG_EMBED_DTB_SOURCE_FILE ?= qcom/qcs615-ride.dts

CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
# PAS starts the ADSP (PAS ID 1) and the CDSP (18) without authenticating
# their images.
$(call force,CFG_QCOM_PAS_AUTH,n,no PAS image authentication on Talos)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
