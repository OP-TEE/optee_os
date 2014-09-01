link-out-dir = $(out-dir)

link-script = $(TA_DEV_KIT_DIR)/src/user_ta_elf_arm.lds
link-script-pp = $(link-out-dir)ta.lds

FIX_TA_BINARY = $(TA_DEV_KIT_DIR)/scripts/fix_ta_binary


all: $(link-out-dir)$(binary).elf $(link-out-dir)$(binary).dmp \
	$(link-out-dir)$(binary).bin
cleanfiles += $(link-out-dir)$(binary).elf $(link-out-dir)$(binary).dmp
cleanfiles += $(link-out-dir)$(binary).map
cleanfiles += $(link-out-dir)$(binary).bin
cleanfiles += $(link-script-pp)

link-ldflags  = $(LDFLAGS)
link-ldflags += -pie
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)$(binary).map
link-ldflags += --sort-section=alignment

# Macro to reverse a list
reverse = $(if $(wordlist 2,2,$(1)),$(call reverse,$(wordlist 2,$(words $(1)),$(1))) $(firstword $(1)),$(1))

link-ldadd  = $(LDADD)
link-ldadd += $(addprefix -L,$(libdirs))
link-ldadd += $(addprefix -l,$(call reverse,$(libnames)))
ldargs-$(binary).elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcc)


$(link-script-pp): $(link-script) $(MAKEFILE_LIST)
	@echo '  CPP     $@'
	$(q)cat < $< > $@


$(link-out-dir)$(binary).elf: $(objs) $(libdeps) $(link-script-pp)
	@echo '  LD      $@'
	$(q)$(LD) $(ldargs-$(binary).elf) -o $@

$(link-out-dir)$(binary).dmp: $(link-out-dir)$(binary).elf
	@echo '  OBJDUMP $@'
	$(q)$(OBJDUMP) -l -x -d $< > $@

$(link-out-dir)$(binary).bin: $(link-out-dir)$(binary).elf
	@echo '  OBJCOPY $@'
	$(q)$(OBJCOPY) -O binary $< $@
	$(q)$(FIX_TA_BINARY) $< $@
