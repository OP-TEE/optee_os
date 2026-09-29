include core/arch/arm/kernel/link.mk

# NOTE: Since we need to reference an ELF file in the .bif file to make PLM
#       firmware really recognize OP-TEE OS as a SEL-1 binary and provide
#       matching "handoff" parameters to ATF (API id 0x70b,
#       get_atf_handoff_params), we wrap the regular tee-raw.bin file in ELF
#       format with a single .text section and the appropriate entry point.
#
#       The tee.elf file cannot be used directly, since OP-TEE OS entry code
#       (entry_a64.S) depends on a struct boot_embdata placed right at symbol
#       __data_end. The script gen_tee_bin.py does this placement while crafting
#       tee-raw.bin (and similarly tee.bin) from tee.elf.

cleanfiles += $(link-out-dir)/tee-raw.bin.o
$(link-out-dir)/tee-raw.bin.o: $(link-out-dir)/tee-raw.bin
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) \
		-I binary -O elf64-littleaarch64 -B aarch64 \
		--rename-section .data=.text \
		--set-section-flags .text=alloc,code,load,readonly,contents \
		$< $@

all: $(link-out-dir)/tee-raw.bin.elf
cleanfiles += $(link-out-dir)/tee-raw.bin.elf
$(link-out-dir)/tee-raw.bin.elf: $(link-out-dir)/tee-raw.bin.o
	@$(cmd-echo-silent) '  LD      $@'
	$(q)ADDR=`printf 0x%x $$(($(subst UL,,$(CFG_TZDRAM_START))))`; \
		$(LDcore) -Ttext $$ADDR -e $$ADDR $< -o $@
