BINARY=bc50d971-d4c9-42c4-82cb-343fb7f37896

O ?= ../out/fTPM
WOLF_ROOT := ../../../../external/wolfssl/
TPM_ROOT := ../../../../

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean: clean_stripped_file
.PHONY: clean_stripped_file
clean_stripped_file:
	rm -f $(BINARY).stripped.elf

