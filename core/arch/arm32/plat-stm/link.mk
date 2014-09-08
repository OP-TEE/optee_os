link-out-dir = $(out-dir)/core

link-script = $(platform-dir)/tz-template.lds
link-script-pp = $(link-out-dir)/tz.lds

all: $(link-out-dir)/tee.elf $(link-out-dir)/tee.dmp $(link-out-dir)/tee.bin
all: $(link-out-dir)/tee.symb_sizes
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.dmp $(link-out-dir)/tee.map
cleanfiles += $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.symb_sizes
cleanfiles += $(link-script-pp)

link-ldflags  = $(LDFLAGS)
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment

link-ldadd  = $(LDADD)
link-ldadd += $(libfiles)
ldargs-tee.elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcc)


$(link-script-pp): $(link-script) $(MAKEFILE_LIST)
	@echo '  SED     $@'
	$(q)sed -e "s/%in_TEE_SCATTER_START%/$(TEE_SCATTER_START)/g" < $< > $@


$(link-out-dir)/tee.elf: $(objs) $(libdeps) $(link-script-pp)
	@echo '  LD      $@'
	$(q)$(LD) $(ldargs-tee.elf) -o $@

$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@echo '  OBJDUMP $@'
	$(q)$(OBJDUMP) -l -x -d $< > $@

$(link-out-dir)/tee.bin: $(link-out-dir)/tee.elf
	@echo '  OBJCOPY $@'
	$(q)$(OBJCOPY) -O binary $< $@

$(link-out-dir)/tee.symb_sizes: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
	$(q)$(NM) --print-size --reverse-sort --size-sort $< > $@
