global-incdirs-y += include

srcs-y += tee_api_property.c
srcs-y += tee_user_mem.c
srcs-y += abort.c
srcs-y += trace_ext.c
srcs-y += assert.c
srcs-y += base64.c
srcs-y += tee_api_arith.c
srcs-y += tee_api.c
srcs-y += tee_api_objects.c
srcs-y += tee_api_operations.c
srcs-y += tee_api_se.c
srcs-y += tee_api_panic.c
srcs-y += utf8.c
srcs-y += image.c
srcs-y += image_png.c
srcs-y += font.c

# Need to locate font.h from generated sources
incdirs-y += .

gensrcs-y += default_bold
produce-additional-default_bold = default_bold.h
produce-default_bold = default_bold.c
depends-default_bold := scripts/render_font.py \
		$(sub-dir)/amble/Amble-Bold.ttf
recipe-default_bold := scripts/render_font.py \
		--font_file $(sub-dir)/amble/Amble-Bold.ttf \
		--font_size 20 --font_name default_bold \
		--out_dir $(sub-dir-out)

gensrcs-y += default_regular
produce-additional-default_regular = default_regular.h
produce-default_regular = default_regular.c
depends-default_regular := scripts/render_font.py \
		$(sub-dir)/amble/Amble-Regular.ttf
recipe-default_regular := scripts/render_font.py \
		--font_file $(sub-dir)/amble/Amble-Regular.ttf \
		--font_size 20 --font_name default_regular \
		--out_dir $(sub-dir-out)

subdirs-y += arch/$(ARCH)
