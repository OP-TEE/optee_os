include core/arch/arm/kernel/link.mk

all: $(link-out-dir)/tee.srec
cleanfiles += $(link-out-dir)/tee.srec

cleanfiles += $(link-out-dir)/tee-raw.bin
$(link-out-dir)/tee-raw.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)scripts/gen_tee_bin.py --input $< --out_tee_raw_bin $@

cleanfiles += $(link-out-dir)/tee.srec
$(link-out-dir)/tee.srec: $(link-out-dir)/tee-raw.bin
	@$(cmd-echo-silent) '  SREC    $@'
	$(q)$(OBJCOPYcore) -I binary -O srec $< $@

