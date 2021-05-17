// SPDX-License-Identifier: BSD-2-Clause
/*
 * (c) 2021 Jorge Ramirez <jorge@foundries.io>, Foundries Ltd.
 */

#include <arm.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>

#define RNG_VER			0x00
#define RNG_CMD			0x04
#define RNG_CR			0x08
#define RNG_SR			0x0C
#define RNG_ESR			0x10
#define RNG_OUT			0x14

#define RNG_CMD_CLR_INT		BIT(4)
#define RNG_CMD_CLR_ERR		BIT(5)

#define RNG_CR_AR		BIT(4)
#define RNG_CR_MASK_DONE	BIT(5)
#define RNG_CR_MASK_ERROR	BIT(6)

#define RNG_SR_ST_DONE		BIT(4)
#define RNG_SR_SEED_DONE	BIT(5)
#define RNG_SR_ERROR		BIT(16)
#define RNG_SR_FIFO_LEVEL_SHIFT	8
#define RNG_SR_FIFO_LEVEL_MASK	GENMASK_32(11, RNG_SR_FIFO_LEVEL_SHIFT)

#define RNG_VER_TYPE_SHIFT	28
#define RNG_VER_TYPE_MASK	GENMASK_32(31, RNG_VER_TYPE_SHIFT)

#define RNG_ESR_STATUS_STAT_ERR	BIT(3)

#define RNG_TYPE_RNGA		0
#define RNG_TYPE_RNGB		1
#define RNG_TYPE_RNGC		2

#define SEED_TIMEOUT		2000000
#define IRQ_TIMEOUT		1000000

#define WORDS_IN_FIFO(__rng_sr)  \
	(((__rng_sr) & RNG_SR_FIFO_LEVEL_MASK) >> RNG_SR_FIFO_LEVEL_SHIFT)

#define RNG_TYPE(__rng_vr) \
	(((__rng_vr) & RNG_VER_TYPE_MASK) >> RNG_VER_TYPE_SHIFT)

static struct imx_rng {
	struct io_pa_va base;
	size_t size;
	bool ready;
	uint32_t error;
} rngb = {
	.base.pa = RNGB_BASE,
	.size = 0x4000,
};

static void wait_for_irq(struct imx_rng *rng)
{
	uint64_t tref = timeout_init_us(IRQ_TIMEOUT);
	uint32_t status = 0;

	do {
		rng->error = io_read32(rng->base.va + RNG_ESR);
		status = io_read32(rng->base.va + RNG_SR);

		if (timeout_elapsed(tref))
			panic();

	} while ((status & (RNG_SR_SEED_DONE | RNG_SR_ST_DONE)) == 0);
}

static void irq_clear(struct imx_rng *rng)
{
	io_setbits32(rng->base.va + RNG_CR,
		     RNG_CR_MASK_DONE | RNG_CR_MASK_ERROR);
	io_setbits32(rng->base.va + RNG_CMD,
		     RNG_CMD_CLR_INT | RNG_CMD_CLR_ERR);
}

static void irq_unmask(struct imx_rng *rng)
{
	io_clrbits32(rng->base.va + RNG_CR,
		     RNG_CR_MASK_DONE | RNG_CR_MASK_ERROR);
}

static void rng_seed(struct imx_rng *rng)
{
	uint64_t tref = timeout_init_us(SEED_TIMEOUT);

	irq_clear(rng);
	do {
		irq_unmask(rng);
		/* configure continuous auto-reseed */
		io_setbits32(rng->base.va + RNG_CR, RNG_CR_AR);
		wait_for_irq(rng);
		irq_clear(rng);

		if (timeout_elapsed(tref))
			panic();
	} while (rng->error);
}

static TEE_Result map_controller_static(void)
{
	rngb.base.va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						     rngb.base.pa, rngb.size);
	if (!rngb.base.va)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

#if !defined(CFG_DT)
static TEE_Result map_controller(void)
{
	return map_controller_static();
}
#else
static const char *const rng_match_table[] =  {
	"fsl,imx25-rngb",
};

static TEE_Result map_controller(void)
{
	void *fdt = get_dt();
	unsigned int i = 0;
	int off = -1;

	if (!fdt)
		return map_controller_static();

	for (i = 0; i < ARRAY_SIZE(rng_match_table); i++) {
		off = fdt_node_offset_by_compatible(fdt, 0, rng_match_table[i]);
		if (off >= 0)
			break;
	}

	if (off < 0)
		return map_controller_static();

	if (dt_enable_secure_status(fdt, off))
		return TEE_ERROR_NOT_SUPPORTED;

	if (dt_map_dev(fdt, off, &rngb.base.va, &rngb.size) < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	rngb.base.pa = virt_to_phys((void *)rngb.base.va);

	return TEE_SUCCESS;
}
#endif

TEE_Result crypto_rng_read(void *buf, size_t len)
{
	uint32_t *rngbuf = buf;
	uint32_t status = 0;
	uint32_t val = 0;

	if (!rngb.ready)
		return TEE_ERROR_BAD_STATE;

	assert(buf);

	while (len) {
		status = io_read32(rngb.base.va + RNG_SR);
		if (status & RNG_SR_ERROR)
			return TEE_ERROR_BAD_STATE;

		if (WORDS_IN_FIFO(status)) {
			val = io_read32(rngb.base.va + RNG_OUT);
			if (len > sizeof(uint32_t)) {
				len = len - sizeof(uint32_t);
				memcpy(rngbuf, &val, sizeof(uint32_t));
				rngbuf++;
			} else {
				memcpy(rngbuf, &val, len);
				len = 0;
			}
		}
	}

	return TEE_SUCCESS;
}

uint8_t hw_get_random_byte(void)
{
	uint8_t data = 0;

	if (crypto_rng_read(&data, 1))
		panic();

	return data;
}

void plat_rng_init(void)
{
}

static TEE_Result rngb_init(void)
{
	uint32_t type = 0;

	if (map_controller())
		panic();

	type = RNG_TYPE(io_read32(rngb.base.va + RNG_VER));
	if (type != RNG_TYPE_RNGB && type != RNG_TYPE_RNGC)
		panic();

	rng_seed(&rngb);
	rngb.ready = true;

	return TEE_SUCCESS;
}

driver_init(rngb_init);
