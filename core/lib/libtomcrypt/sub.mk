cppflags-lib-$(libtomcrypt_with_optimize_size) += -DLTC_SMALL_CODE -DLTC_NO_FAST

global-incdirs-y += include

subdirs-y += src
