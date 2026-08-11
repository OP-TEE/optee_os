user-ta-uuid := cff7d191-7ca0-4784-af13-48223b9a4fbe

ifneq ($(PLATFORM),qcom)
user-ta-skip := y
endif

CFG_QCOM_PAS_AUTH ?= n

ifeq ($(CFG_QCOM_PAS_AUTH),y)
CFG_PAS_TA_HEAP_SIZE ?= (512 * 1024)
else
CFG_PAS_TA_HEAP_SIZE ?= (4 * 1024)
endif
