subdirs-y += crypto
subdirs-y += drivers
subdirs-y += kernel
subdirs-y += mm
subdirs-y += pta
subdirs-y += tee

ifeq ($(CFG_WITH_USER_TA),y)
gensrcs-y += ta_pub_key
produce-ta_pub_key = ta_pub_key.c
depends-ta_pub_key = $(TA_PUBLIC_KEY) scripts/pem_to_pub_c.py
recipe-ta_pub_key = $(PYTHON3) scripts/pem_to_pub_c.py --prefix ta_pub_key \
		--key $(TA_PUBLIC_KEY) --out $(sub-dir-out)/ta_pub_key.c

gensrcs-y += ldelf
produce-ldelf = ldelf_hex.c
depends-ldelf = scripts/gen_ldelf_hex.py $(out-dir)/ldelf/ldelf.elf
recipe-ldelf = $(PYTHON3) scripts/gen_ldelf_hex.py --input $(out-dir)/ldelf/ldelf.elf \
			--output $(sub-dir-out)/ldelf_hex.c
endif

ifeq ($(CFG_WITH_USER_TA)-$(CFG_EARLY_TA),y-y)
ifeq ($(CFG_EARLY_TA_COMPRESS),y)
early-ta-compress = --compress
endif
define process_early_ta
early-ta-$1-uuid := $(firstword $(subst ., ,$(notdir $1)))
gensrcs-y += early-ta-$1
produce-early-ta-$1 = early_ta_$$(early-ta-$1-uuid).c
depends-early-ta-$1 = $1 scripts/ts_bin_to_c.py
recipe-early-ta-$1 = $(PYTHON3) scripts/ts_bin_to_c.py $(early-ta-compress) \
		--ta $1 --out $(sub-dir-out)/early_ta_$$(early-ta-$1-uuid).c
endef
$(foreach f, $(EARLY_TA_PATHS), $(eval $(call process_early_ta,$(f))))
$(foreach f, $(CFG_IN_TREE_EARLY_TAS), $(eval $(call \
	process_early_ta,$(out-dir)/ta/$(f).stripped.elf)))
endif

define process_secure_partition
sp-$1-uuid := $(firstword $(subst ., ,$(notdir $1)))
gensrcs-y += sp-$1
produce-sp-$1 = sp_$$(sp-$1-uuid).c
depends-sp-$1 = $1 scripts/ts_bin_to_c.py
recipe-sp-$1 = $(PYTHON3) scripts/ts_bin_to_c.py --compress --sp $1 \
		--out $(sub-dir-out)/sp_$$(sp-$1-uuid).c
endef
$(foreach f, $(SP_PATHS), $(eval $(call process_secure_partition,$(f))))

ifeq ($(CFG_EMBED_DTB),y)
core-embed-fdt-dts = $(arch-dir)/dts/$(CFG_EMBED_DTB_SOURCE_FILE)
core-embed-fdt-dtb = $(out-dir)/$(arch-dir)/dts/$(CFG_EMBED_DTB_SOURCE_FILE:.dts=.dtb)
core-embed-fdt-c = $(out-dir)/$(arch-dir)/dts/$(CFG_EMBED_DTB_SOURCE_FILE:.dts=.c)
gensrcs-y += embedded_secure_dtb
produce-embedded_secure_dtb = arch/$(ARCH)/dts/$(CFG_EMBED_DTB_SOURCE_FILE:.dts=.c)
depends-embedded_secure_dtb = $(core-embed-fdt-dtb) scripts/bin_to_c.py
recipe-embedded_secure_dtb = $(PYTHON3) scripts/bin_to_c.py \
				--bin $(core-embed-fdt-dtb) \
				--vname embedded_secure_dtb \
				--out $(core-embed-fdt-c)
$(eval $(call gen-dtb-file,$(core-embed-fdt-dts),$(core-embed-fdt-dtb)))
endif

ifeq ($(CFG_SHOW_CONF_ON_BOOT),y)
conf-mk-xz-base64 := $(sub-dir-out)/conf.mk.xz.base64
cleanfiles += $(conf-mk-xz-base64)

$(conf-mk-xz-base64): $(conf-mk-file)
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)tail +3 $< | xz | base64 -w 100 >$@

gensrcs-y += conf_str
produce-conf_str = conf.mk.xz.base64.c
depends-conf_str = $(conf-mk-xz-base64)
recipe-conf_str = $(PYTHON3) scripts/bin_to_c.py --text --bin $(conf-mk-xz-base64) \
			--out $(sub-dir-out)/conf.mk.xz.base64.c \
			--vname conf_str
endif

ifneq ($(CFG_STMM_PATH),)
gensrcs-y += stmm
produce-stmm = stmm_hex.c
depends-stmm = scripts/gen_stmm_hex.py $(CFG_STMM_PATH)
recipe-stmm = scripts/gen_stmm_hex.py --input $(CFG_STMM_PATH) \
			--output $(sub-dir-out)/stmm_hex.c
cleanfiles += $(sub-dir-out)/stmm_hex.c
endif
