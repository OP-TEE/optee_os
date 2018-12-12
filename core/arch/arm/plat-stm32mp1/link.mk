include core/arch/arm/kernel/link.mk

# Create stm32 formatted images from the native binary images

define stm32image_cmd
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)./core/arch/arm/plat-stm32mp1/scripts/stm32image.py \
		--load 0 --entry 0
endef

all: $(link-out-dir)/tee-header_v2.stm32
cleanfiles += $(link-out-dir)/tee-header_v2.stm32
$(link-out-dir)/tee-header_v2.stm32: $(link-out-dir)/tee-header_v2.bin
	$(stm32image_cmd) --source $< --dest $@ --bintype 0x20

all: $(link-out-dir)/tee-pager_v2.stm32
cleanfiles += $(link-out-dir)/tee-pager_v2.stm32
$(link-out-dir)/tee-pager_v2.stm32: $(link-out-dir)/tee-pager_v2.bin
	$(stm32image_cmd) --source $< --dest $@ --bintype 0x21

all: $(link-out-dir)/tee-pageable_v2.stm32
cleanfiles += $(link-out-dir)/tee-pageable_v2.stm32
$(link-out-dir)/tee-pageable_v2.stm32: $(link-out-dir)/tee-pageable_v2.bin
	$(stm32image_cmd) --source $< --dest $@ --bintype 0x22
