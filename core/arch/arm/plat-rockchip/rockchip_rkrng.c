// SPDX-License-Identifier: BSD-2-Clause
/*
 * Rockchip RKRNG secure TRNG driver for RK3576.
 *
 * The RKRNG IP is found on RK3576/RK3562/RK3528. This driver targets the
 * secure instance (RKRNG_S_BASE) accessible only from secure world.
 *
 * Register layout matches the Linux rockchip-rng.c driver (rk3576_rng_*).
 */

#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include "rockchip_rkrng.h"

static vaddr_t rkrng_base;
static unsigned int rkrng_lock = SPINLOCK_UNLOCK;

static TEE_Result rkrng_read_block(void *buf)
{
	uint64_t timeout = timeout_init_us(RKRNG_POLL_TIMEOUT_US);
	uint32_t state = 0;

	/* Request one TRNG block — upper 16 bits are write-mask */
	io_write32(rkrng_base + RKRNG_CTRL,
		   RKRNG_CTRL_REQ_TRNG | (RKRNG_CTRL_REQ_TRNG << 16));

	/* Poll until data ready */
	do {
		state = io_read32(rkrng_base + RKRNG_STATE);
		if (state & RKRNG_STATE_TRNG_RDY)
			break;
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
	} while (true);

	/* Clear ready flag */
	io_write32(rkrng_base + RKRNG_STATE, RKRNG_STATE_TRNG_RDY);

	memcpy(buf, (void *)(rkrng_base + RKRNG_TRNG_DATA0), RKRNG_READ_LEN);

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t block[RKRNG_READ_LEN] = { };
	size_t off = 0;
	uint32_t exceptions = 0;
	TEE_Result res = TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&rkrng_lock);

	/*
	 * Lazy-map on first use: hw_get_random_bytes() may be called from
	 * service_init context (e.g. HUK derivation) before driver_init()
	 * has run.  phys_to_virt_io() is safe here because core_init_mmu_map
	 * runs in entry_a64.S well before any initcall.
	 */
	if (!rkrng_base)
		rkrng_base = (vaddr_t)phys_to_virt_io(RKRNG_S_BASE,
						       RKRNG_S_SIZE);

	if (!rkrng_base) {
		cpu_spin_unlock_xrestore(&rkrng_lock, exceptions);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	while (off < len) {
		size_t chunk = 0;

		res = rkrng_read_block(block);
		if (res)
			break;

		chunk = MIN(RKRNG_READ_LEN, len - off);
		memcpy((uint8_t *)buf + off, block, chunk);
		off += chunk;
	}

	cpu_spin_unlock_xrestore(&rkrng_lock, exceptions);
	memzero_explicit(block, sizeof(block));
	return res;
}

static TEE_Result rkrng_init(void)
{
	rkrng_base = (vaddr_t)phys_to_virt_io(RKRNG_S_BASE, RKRNG_S_SIZE);
	if (!rkrng_base) {
		EMSG("RK3576: failed to map RKRNG_S @ 0x%x", RKRNG_S_BASE);
		return TEE_ERROR_GENERIC;
	}
	IMSG("RK3576: RKRNG_S hardware RNG ready");
	return TEE_SUCCESS;
}

driver_init(rkrng_init);
