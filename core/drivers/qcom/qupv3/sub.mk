ifeq ($(CFG_QCOM_QUPV3_FW_LOAD),y)
srcs-y += qup_fw_load.c
subdirs-y += platform
endif
