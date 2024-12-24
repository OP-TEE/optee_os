include core/arch/arm/kernel/link.mk

all: $(link-out-dir)/optee.rom
cleanfiles += $(link-out-dir)/optee.rom
$(link-out-dir)/optee.rom: $(link-out-dir)/tee-pager_v2.bin
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) core/arch/arm/plat-telechips/scripts/tcmktool.py $< $@ $(TCMKTOOL_IMGNAME) \
		$(CFG_OPTEE_REVISION_MAJOR).$(CFG_OPTEE_REVISION_MINOR)$(CFG_OPTEE_REVISION_EXTRA) \
		$(CFG_TZDRAM_START) $(PLATFORM_FLAVOR)
