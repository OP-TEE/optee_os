include core/arch/arm/kernel/link.mk

all: $(link-out-dir)/tee.srec
cleanfiles += $(link-out-dir)/tee.srec
$(link-out-dir)/tee.srec: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  SREC    $@'
	$(q)$(OBJCOPYcore) -O srec $< $@
