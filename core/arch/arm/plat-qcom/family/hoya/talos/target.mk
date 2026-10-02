$(call force,CFG_QCOM_RAMBLUR_PIMEM_V2,y,Talos has RAMBLUR v2.3)

# The TZ Apps region of the QCS615 memory map backs RAMBLUR window 2
CFG_TA_RAM_VA_SIZE ?= 0x1c00000

$(call force,CFG_EMBED_DTB,y)
CFG_EMBED_DTB_SOURCE_FILE ?= qcom/qcs615-ride.dts
