user-ta-uuid := cff7d191-7ca0-4784-af13-48223b9a4fbe

ifneq ($(PLATFORM),qcom)
user-ta-skip := y
endif

CFG_QCOM_PAS_AUTH ?= n

# Platform-specific configs may override these default values
CFG_PAS_MD_SLOTS ?= 8
CFG_PAS_TA_HEAP_SIZE ?= (128 * 1024)
