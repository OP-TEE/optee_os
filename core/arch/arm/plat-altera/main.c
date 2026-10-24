// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Altera Corporation.
 */

#include <console.h>
#include <crypto/crypto.h>
#include <drivers/serial8250_uart.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/cache_helpers.h>
#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include "platform_config.h"

static struct serial8250_uart_data uart_console;

void plat_console_init(void)
{
	serial8250_uart_init(&uart_console,
			     CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ,
			     CONSOLE_BAUDRATE);
	register_serial_console(&uart_console.chip);
}

/* Map UART registers as I/O memory */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			SERIAL8250_UART_REG_SIZE);

/* System Manager — sdm_svc PTA SDM stream control / remapper */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SYSMGR_BASE, SYSMGR_SIZE);

/* Register main DDR for dynamic shared memory */
register_ddr(DRAM0_BASE, DRAM0_SIZE);

/*
 * Seed Fortuna (CFG_WITH_SOFTWARE_PRNG) from the SDM TRNG via ATF async FCS
 * SiP SMCs. plat_get_aslr_seed() runs before core_init_mmu_map() / console:
 * do not use virt_to_phys() or IMSG; bounce PA is VA under ATF early TZDRAM
 * identity map. Unprovisioned devices fail session open; boot continues.
 */
#define SDM_SEED_SMC_OPEN_CS		UINT32_C(0x4200013A)
#define SDM_SEED_SMC_CLOSE_CS		UINT32_C(0x4200013B)
#define SDM_SEED_SMC_RANDOM_EXT		UINT32_C(0x4200012D)
#define SDM_SEED_SMC_RESP_POLL		UINT32_C(0x420000C8)
#define SDM_SEED_SMC_STATUS_OK		UINT32_C(0)
#define SDM_SEED_POLL_MAX		10000
#define SDM_SEED_HDR_BYTES		12U
#define SDM_SEED_MAX_BYTES		32U
#define SDM_SEED_BOUNCE_SIZE \
	(SDM_SEED_HDR_BYTES + SDM_SEED_MAX_BYTES)

static TEE_Result sdm_seed_poll(struct thread_smc_args *out)
{
	struct thread_smc_args args = { };
	int i = 0;

	for (i = 0; i < SDM_SEED_POLL_MAX; i++) {
		memset(&args, 0, sizeof(args));
		args.a0 = SDM_SEED_SMC_RESP_POLL;
		thread_smccc(&args);
		if ((uint32_t)args.a0 == SDM_SEED_SMC_STATUS_OK)
			break;
	}

	if (i == SDM_SEED_POLL_MAX || args.a1 != 0)
		return TEE_ERROR_GENERIC;

	if (out)
		*out = args;

	return TEE_SUCCESS;
}

static TEE_Result sdm_get_rng_bytes(size_t len, uint8_t *bounce,
				    paddr_t phys, void *out)
{
	struct thread_smc_args args = { };
	struct thread_smc_args poll_res = { };
	struct thread_smc_args close_args = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t session_id = 0;

	memset(bounce, 0, SDM_SEED_HDR_BYTES + len);
	cache_op_inner(DCACHE_AREA_CLEAN, bounce, SDM_SEED_HDR_BYTES + len);

	memset(&args, 0, sizeof(args));
	args.a0 = SDM_SEED_SMC_OPEN_CS;
	thread_smccc(&args);
	if ((uint32_t)args.a0 != SDM_SEED_SMC_STATUS_OK)
		return TEE_ERROR_NOT_SUPPORTED;

	res = sdm_seed_poll(&poll_res);
	if (res != TEE_SUCCESS)
		goto close;

	session_id = (uint32_t)poll_res.a2;

	memset(&args, 0, sizeof(args));
	args.a0 = SDM_SEED_SMC_RANDOM_EXT;
	args.a2 = session_id;
	args.a4 = (uint64_t)phys;
	args.a5 = (uint64_t)len;
	thread_smccc(&args);
	if ((uint32_t)args.a0 != SDM_SEED_SMC_STATUS_OK) {
		res = TEE_ERROR_GENERIC;
		goto close;
	}

	res = sdm_seed_poll(NULL);
	if (res != TEE_SUCCESS)
		goto close;

	cache_op_inner(DCACHE_AREA_INVALIDATE, bounce,
		       SDM_SEED_HDR_BYTES + len);
	memcpy(out, bounce + SDM_SEED_HDR_BYTES, len);

close:
	memset(&close_args, 0, sizeof(close_args));
	close_args.a0 = SDM_SEED_SMC_CLOSE_CS;
	close_args.a2 = session_id;
	thread_smccc(&close_args);
	if ((uint32_t)close_args.a0 == SDM_SEED_SMC_STATUS_OK)
		sdm_seed_poll(NULL);

	return res;
}

unsigned long plat_get_aslr_seed(void)
{
	uint8_t bounce[SDM_SEED_BOUNCE_SIZE] __aligned(4);
	unsigned long seed = 0;
	paddr_t phys = (paddr_t)(uintptr_t)bounce;

	sdm_get_rng_bytes(sizeof(seed), bounce, phys, &seed);
	return seed;
}

static TEE_Result sdm_seed_prng_pool(void)
{
	uint8_t bounce[SDM_SEED_BOUNCE_SIZE] __aligned(4);
	uint8_t entropy[SDM_SEED_MAX_BYTES] = { };
	static unsigned int pnum;
	TEE_Result res = TEE_SUCCESS;

	res = sdm_get_rng_bytes(SDM_SEED_MAX_BYTES, bounce,
				virt_to_phys(bounce), entropy);
	if (res == TEE_SUCCESS) {
		crypto_rng_add_event(CRYPTO_RNG_SRC_NONSECURE, &pnum,
				     entropy, sizeof(entropy));
		memset(entropy, 0, sizeof(entropy));
		IMSG("SDM TRNG: PRNG seeded with %u bytes",
		     SDM_SEED_MAX_BYTES);
	} else {
		IMSG("SDM TRNG unavailable; PRNG uses internal entropy");
	}

	return TEE_SUCCESS;
}

driver_init(sdm_seed_prng_pool);
