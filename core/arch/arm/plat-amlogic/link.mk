include core/arch/arm/kernel/link.mk

# Create BL32 image from the native binary images

define aml_bin2img_cmd
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)./core/arch/arm/plat-amlogic/scripts/aml_bin2img.py
endef

ifneq (,$(filter $(PLATFORM_FLAVOR),axg))
all: $(link-out-dir)/bl32.img
cleanfiles += $(link-out-dir)/bl32.img
$(link-out-dir)/bl32.img: $(link-out-dir)/tee-pager_v2.bin
	$(aml_bin2img_cmd) --source $< --dest $@ --entry 0x5300000 \
			   --res_mem_start 0x5300000 --res_mem_size 0x1000000 \
			   --sec_mem_start 0x5300000 --sec_mem_size 0xc00000
endif
