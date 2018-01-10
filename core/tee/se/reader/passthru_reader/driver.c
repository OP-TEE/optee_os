// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <platform_config.h>
#include <io.h>
#include <initcall.h>
#include <tee/se/reader/interface.h>
#include <mm/core_memprot.h>

#include <trace.h>

#include <stdlib.h>

#include "pcsc.h"
#include "reader.h"

struct pcsc_context {
	uint32_t mmio_base;
	uint8_t num_readers;
	struct pcsc_reader *readers;
};
static struct pcsc_context pcsc_context;

register_phys_mem(MEM_AREA_IO_SEC, PCSC_BASE, 0x1000);

static uint32_t pcsc_read_reg(struct pcsc_context *ctx, uint8_t offset)
{
	return read32(ctx->mmio_base + offset);
}

static void pcsc_write_reg(struct pcsc_context *ctx, uint8_t offset,
		uint32_t value) __attribute__((unused));
static void pcsc_write_reg(struct pcsc_context *ctx, uint8_t offset,
		uint32_t value)
{
	write32(ctx->mmio_base + offset, value);
}

static TEE_Result populate_readers(struct pcsc_context *ctx)
{
	int i;
	uint32_t reader_mmio_base = ctx->mmio_base + PCSC_REG_MAX;
	TEE_Result ret;

	ctx->readers = malloc(sizeof(struct pcsc_reader) * ctx->num_readers);
	if (!ctx->readers)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < ctx->num_readers; i++) {
		uint32_t mmio_base =
			reader_mmio_base + (i * PCSC_REG_READER_MAX);
		struct pcsc_reader *r = &ctx->readers[i];

		init_reader(r, i, mmio_base);
		ret = tee_se_manager_register_reader(&r->se_reader);
		if (ret != TEE_SUCCESS)
			goto err_rollback;
	}

	return TEE_SUCCESS;

err_rollback:
	i--;
	while (i) {
		tee_se_manager_unregister_reader(&ctx->readers[i].se_reader);
		i--;
	}
	free(ctx->readers);
	return ret;
}

static void context_init(struct pcsc_context *ctx)
{
	ctx->mmio_base = (vaddr_t)phys_to_virt(PCSC_BASE, MEM_AREA_IO_SEC);
	if (ctx->mmio_base) {
		ctx->num_readers = pcsc_read_reg(ctx, PCSC_REG_NUM_READERS);
		DMSG("%d reader detected", ctx->num_readers);
	}
}

static TEE_Result pcsc_passthru_reader_init(void)
{
	TEE_Result ret;
	struct pcsc_context *ctx = &pcsc_context;

	context_init(ctx);

	ret = populate_readers(ctx);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

driver_init(pcsc_passthru_reader_init);
