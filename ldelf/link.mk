link-script$(sm) = ldelf/ldelf.ld.S
link-script-pp$(sm) = $(link-out-dir$(sm))/ldelf.lds
link-script-dep$(sm) = $(link-out-dir$(sm))/.ldelf.ld.d

.PHONY: ldelf
ldelf: $(link-out-dir$(sm))/ldelf.dmp
ldelf: $(link-out-dir$(sm))/ldelf.elf
all: ldelf

cleanfiles += $(link-out-dir$(sm))/ldelf.dmp
cleanfiles += $(link-out-dir$(sm))/ldelf.map
cleanfiles += $(link-out-dir$(sm))/ldelf.elf
cleanfiles += $(link-script-pp$(sm)) $(link-script-dep$(sm))

link-ldflags  = -pie -static --gc-sections
link-ldflags += -T $(link-script-pp$(sm))
link-ldflags += -Map=$(link-out-dir$(sm))/ldelf.map
link-ldflags += --sort-section=alignment
link-ldflags += -z max-page-size=4096 # OP-TEE always uses 4K alignment
link-ldflags += $(link-ldflags$(sm))

link-ldadd  = $(addprefix -L,$(libdirs))
link-ldadd += --start-group $(addprefix -l,$(libnames)) --end-group
ldargs-ldelf.elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcc$(sm))

link-script-cppflags-$(sm) := \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinc$(sm)) $(CPPFLAGS) \
		$(addprefix -I,$(incdirs$(sm)) $(link-out-dir$(sm))) \
		$(cppflags$(sm)))

-include $(link-script-dep$(sm))

link-script-pp-makefiles$(sm) = $(filter-out %.d %.cmd,$(MAKEFILE_LIST))

define gen-link-t
$(link-script-pp$(sm)): $(link-script$(sm)) $(conf-file) \
			$(link-script-pp-makefiles$(sm))
	@$(cmd-echo-silent) '  CPP     $$@'
	$(q)mkdir -p $$(dir $$@)
	$(q)$(CPP$(sm)) -P -MT $$@ -MD -MF $(link-script-dep$(sm)) \
		$(link-script-cppflags-$(sm)) $$< -o $$@

$(link-out-dir$(sm))/ldelf.elf: $(objs) $(libdeps) $(link-script-pp$(sm))
	@$(cmd-echo-silent) '  LD      $$@'
	$(q)$(LD$(sm)) $(ldargs-ldelf.elf) -o $$@

$(link-out-dir$(sm))/ldelf.dmp: $(link-out-dir$(sm))/ldelf.elf
	@$(cmd-echo-silent) '  OBJDUMP $$@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $$< > $$@
endef

$(eval $(call gen-link-t))
