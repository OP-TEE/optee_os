# REMOTEPROC TA heap size can be customized if 4kB is not enough
CFG_REMOTEPROC_TA_HEAP_SIZE ?= (4 * 1024)

global-incdirs-y += include
srcs-y += remoteproc_core.c
srcs-y += elf_parser.c
