// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */
/*
 * Support for Thread-Local Storage (TLS) ABIs for ARMv7/Aarch32 and Aarch64.
 *
 * TAs are currently single-threaded, so the only benefit of implementing these
 * ABIs is to support toolchains that need them even when the target program is
 * single-threaded. Such as, the g++ compiler from the GCC toolchain targeting a
 * "Posix thread" Linux runtime, which OP-TEE has been using for quite some time
 * (arm-linux-gnueabihf-* and aarch64-linux-gnu-*). This allows building C++ TAs
 * without having to build a specific toolchain with --disable-threads.
 *
 * This implementation is based on [1].
 *
 *  - "TLS data structures variant 1" (section 3): the AArch64 compiler uses the
 *    TPIDR_EL0 to access TLS data directly. This assumes a specific layout for
 *    the TCB, and (for shared objects) the use of R_AARCH64_TLS_TPREL
 *    relocations.
 *  - The "General Dynamic access model" (section 4.1): the ARMv7/Aarch32
 *    compiler inserts calls to the __tls_get_addr() function which has to be
 *    implemented by the runtime library. The function takes a module ID and an
 *    offset parameter, which are provided thanks to R_ARM_TLS_DTPMOD32 and
 *    R_ARM_TLS_DTPOFF32 relocations.
 *
 * In addition, dl_iterate_phdr() is implemented here, because it is used by the
 * g++ Aarch64 exception handling and it does use the TCB to provide TLS
 * information to the caller.
 *
 * [1] "ELF Handling For Thread-Local Storage"
 *     https://www.akkadia.org/drepper/tls.pdf
 */

#include <arm64_user_sysreg.h>
#include <assert.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "user_ta_header.h"

/* DTV - Dynamic Thread Vector
 *
 * Maintains an array of pointers to TLS data for each module in the TCB. Each
 * module that has a TLS segment has an entry (and consequently, some space in
 * the tcb_head::tls buffer). The index is the "module ID".
 * dtv[0].size is the number of elements in the vector
 * dtv[1].tls points to TLS for the main executable (may be NULL)
 * tls[2 .. (size-1)] are for shared libraries
 */
union dtv {
	unsigned long size;
	uint8_t *tls;
};

#define DTV_SIZE(size) (sizeof(union dtv) + (size))

/* Thread Control Block */
struct tcb_head {
	/* Two words are reserved as per the "TLS variant 1" ABI */
	union dtv *dtv;
	unsigned long reserved;
	/*
	 * The rest of the structure contains the TLS blocks for each ELF module
	 * having a PT_TLS segment. Each block is a copy of the .tdata section
	 * plus some zero-initialized space for .tbss.
	 */
	uint8_t tls[];
};

/*
 * Since TAs are single threaded, only one TCB is needed. This would need to
 * change if multi-threading is introduced.
 */
static struct tcb_head *_tcb;
static size_t _tls_size;

#define TCB_SIZE(tls_size) (sizeof(*_tcb) + (tls_size))

/*
 * Initialize or update the TCB.
 * Called on application initialization and when additional shared objects are
 * loaded via dlopen().
 */
void __utee_tcb_init(void)
{
	struct dl_phdr_info *dlpi = NULL;
	const Elf_Phdr *phdr = NULL;
	size_t total_size = 0;
	size_t size = 0;
	size_t i = 0;
	size_t j = 0;

	/* Compute the size needed for all the TLS blocks */
	for (i = 0; i < __elf_phdr_info.count; i++) {
		dlpi = __elf_phdr_info.dlpi + i;
		for (j = 0; j < dlpi->dlpi_phnum; j++) {
			phdr = dlpi->dlpi_phdr + j;
			if (phdr->p_type == PT_TLS) {
				total_size += phdr->p_memsz;
				break;
			}
		}
	}

	/* ELF modules currently cannot be unmapped */
	assert(total_size >= _tls_size);

	if (total_size == _tls_size)
		return;

	/* (Re-)allocate the TCB */
	_tcb = realloc(_tcb, TCB_SIZE(total_size));
	if (!_tcb) {
		EMSG("TCB allocation failed (%zu bytes)", TCB_SIZE(total_size));
		abort();
	}

	/* (Re-)allocate the DTV. + 1 since dtv[0] holds the size */
	size = DTV_SIZE((__elf_phdr_info.count + 1) * sizeof(union dtv));
	_tcb->dtv = realloc(_tcb->dtv, size);
	if (!_tcb->dtv) {
		EMSG("DTV allocation failed (%zu bytes)", size);
		abort();
	}

	/* Copy TLS data to the TCB */
	size = 0;
	for (i = 0; i < __elf_phdr_info.count; i++) {
		dlpi = __elf_phdr_info.dlpi + i;
		for (j = 0; j < dlpi->dlpi_phnum; j++) {
			phdr = dlpi->dlpi_phdr + j;
			if (phdr->p_type != PT_TLS)
				continue;
			if (size + phdr->p_memsz <= _tls_size) {
				/* Already copied */
				break;
			}
			_tcb->dtv[i + 1].tls = _tcb->tls + size;
			/* Copy .tdata */
			memcpy(_tcb->tls + size,
			       (void *)(dlpi->dlpi_addr + phdr->p_vaddr),
			       phdr->p_filesz);
			/* Initialize .tbss */
			memset(_tcb->tls + size + phdr->p_filesz, 0,
			       phdr->p_memsz - phdr->p_filesz);
			size += phdr->p_memsz;
		}
	}
	_tcb->dtv[0].size = i;

	_tls_size = total_size;
#ifdef ARM64
	/*
	 * Aarch64 ABI requirement: the thread pointer shall point to the
	 * thread's TCB. ARMv7 and Aarch32 access the TCB via _tls_get_addr().
	 */
	write_tpidr_el0((vaddr_t)_tcb);
#endif
}

struct tls_index {
	unsigned long module;
	unsigned long offset;
};

void *__tls_get_addr(struct tls_index *ti);

void *__tls_get_addr(struct tls_index *ti)
{
	return _tcb->dtv[ti->module].tls + ti->offset;
}

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *),
		    void *data)
{
	struct dl_phdr_info *dlpi = NULL;
	size_t id = 0;
	size_t i = 0;
	int st = 0;

	/*
	 * dlpi_tls_data is thread-specific so if we were to support
	 * multi-threading, we would need one copy of struct dl_phdr_info per
	 * thread. Could be a pre-allocated area, or could be allocated on the
	 * heap. Doing the latter here so that it would at least work if/when we
	 * add thread support. Further optimization can always come later.
	 */
	dlpi = calloc(1, sizeof(*dlpi));
	if (!dlpi) {
		EMSG("dl_phdr_info allocation failed");
		abort();
	}

	for (i = 0; i < __elf_phdr_info.count; i++) {
		memcpy(dlpi, __elf_phdr_info.dlpi + i, sizeof(*dlpi));
		dlpi->dlpi_tls_data = NULL;
		id = dlpi->dlpi_tls_modid;
		if (id)
			dlpi->dlpi_tls_data = _tcb->dtv[id].tls;
		st = callback(dlpi, sizeof(*dlpi), data);
	}

	free(dlpi);
	return st;
}
