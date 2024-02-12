/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __MM_CORE_MEMPROT_H
#define __MM_CORE_MEMPROT_H

#include <mm/core_mmu.h>
#include <types_ext.h>

/*
 * "pbuf_is" support.
 *
 * core_vbuf_is()/core_pbuf_is() can be used to check if a teecore mapped
 * virtual address or a physical address is "Secure", "Unsecure", "external
 * RAM" and some other fancy attributes.
 *
 * DO NOT use 'buf_is(Secure, buffer)==false' as a assumption that buffer is
 * UnSecured ! This is NOT a valid asumption ! A buffer is certified UnSecured
 * only if 'buf_is(UnSecure, buffer)==true'.
 */

/* memory atttributes */
enum buf_is_attr {
	CORE_MEM_CACHED,
	CORE_MEM_NSEC_SHM,
	CORE_MEM_NON_SEC,
	CORE_MEM_SEC,
	CORE_MEM_TEE_RAM,
	CORE_MEM_TA_RAM,
	CORE_MEM_SDP_MEM,
	CORE_MEM_REG_SHM,
};

/* redirect legacy tee_vbuf_is() and tee_pbuf_is() to our routines */
#define tee_pbuf_is     core_pbuf_is
#define tee_vbuf_is     core_vbuf_is

/* Convenience macros */
#define tee_pbuf_is_non_sec(buf, len) \
		core_pbuf_is(CORE_MEM_NON_SEC, (paddr_t)(buf), (len))

#define tee_pbuf_is_sec(buf, len) \
		core_pbuf_is(CORE_MEM_SEC, (paddr_t)(buf), (len))

#define tee_vbuf_is_non_sec(buf, len) \
		core_vbuf_is(CORE_MEM_NON_SEC, (void *)(buf), (len))

#define tee_vbuf_is_sec(buf, len) \
		core_vbuf_is(CORE_MEM_SEC, (void *)(buf), (len))

/*
 * This function return true if the buf complies with supplied flags.
 * If this function returns false buf doesn't comply with supplied flags
 * or something went wrong.
 *
 * Note that returning false doesn't guarantee that buf complies with
 * the complement of the supplied flags.
 */
bool core_pbuf_is(uint32_t flags, paddr_t pbuf, size_t len);

/*
 * Translates the supplied virtual address to a physical address and uses
 * tee_phys_buf_is() to check the compliance of the buffer.
 */
bool core_vbuf_is(uint32_t flags, const void *vbuf, size_t len);

/*
 * Translate physical address to virtual address using specified mapping.
 * Also tries to find proper mapping which have counterpart translation
 * for specified length of data starting from given physical address.
 * Len parameter can be set to 1 if caller knows that requested (pa + len)
 * doesn`t cross mapping granule boundary.
 * Returns NULL on failure or a valid virtual address on success.
 */
void *phys_to_virt(paddr_t pa, enum teecore_memtypes m, size_t len);

/*
 * Translate physical address to virtual address trying MEM_AREA_IO_SEC
 * first then MEM_AREA_IO_NSEC if not found. Like phys_to_virt() tries
 * to find proper mapping relying on length parameter.
 * Returns NULL on failure or a valid virtual address on success.
 */
void *phys_to_virt_io(paddr_t pa, size_t len);

/*
 * Translate virtual address to physical address
 * Returns 0 on failure or a valid physical address on success.
 */
paddr_t virt_to_phys(void *va);

/*
 * Return runtime usable address, irrespective of whether
 * the MMU is enabled or not. In case of MMU enabled also will be performed
 * check for requested amount of data is present in found mapping.
 */
vaddr_t core_mmu_get_va(paddr_t pa, enum teecore_memtypes type, size_t len);

/*
 * is_unpaged() - report unpaged status of an address
 * @va:		virtual address
 *
 * Returns true if the @va is non-NULL and is in the unpaged area if paging
 * is enabled, else false.
 */
#ifdef CFG_WITH_PAGER
bool is_unpaged(const void *va);
#else
static inline bool is_unpaged(const void *va) { return va; }
#endif

/*
 * is_nexus() - report nexus status of an address
 * @va:		virtual address
 *
 * Returns true if the @va is non-NULL and is in the nexus memory area
 * if ns-virtualization is enabled, else false.
 */
#ifdef CFG_NS_VIRTUALIZATION
bool is_nexus(const void *va);
#else
static inline bool is_nexus(const void *va) { return va; }
#endif

struct io_pa_va {
	paddr_t pa;
	vaddr_t va;
};

/*
 * Helper function to return a physical or virtual address for a device,
 * depending on whether the MMU is enabled or not
 * io_pa_or_va() uses secure mapped IO memory if found or fallback to
 * non-secure mapped IO memory.
 */
vaddr_t io_pa_or_va_secure(struct io_pa_va *p, size_t len);
vaddr_t io_pa_or_va_nsec(struct io_pa_va *p, size_t len);
vaddr_t io_pa_or_va(struct io_pa_va *p, size_t len);

#endif /* __MM_CORE_MEMPROT_H */
