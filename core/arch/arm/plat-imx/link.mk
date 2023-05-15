include core/arch/arm/kernel/link.mk

.PHONY: uTee
uTee: $(link-out-dir)/uTee
cleanfiles += $(link-out-dir)/uTee
$(link-out-dir)/uTee: $(link-out-dir)/tee-raw.bin
	@$(cmd-echo-silent) '  MKIMAGE $@'
	$(q)ADDR=`printf 0x%x $$(($(subst UL,,$(CFG_TZDRAM_START))))`; \
		mkimage -A arm -O linux -C none -a $$ADDR -e $$ADDR -d $< $@
