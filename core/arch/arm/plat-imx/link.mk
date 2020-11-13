include core/arch/arm/kernel/link.mk

all: $(link-out-dir)/tee-raw.bin

cleanfiles += $(link-out-dir)/tee-raw.bin
$(link-out-dir)/tee-raw.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)scripts/gen_tee_bin.py --input $< --out_tee_raw_bin $@
