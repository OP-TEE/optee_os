// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, STMicroelectronics
 */
#include <assert.h>
#include <compiler.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <dt-bindings/reset/stm32mp1-resets.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <stm32_util.h>
#include <tee_api_defines.h>
#include <util.h>

#define TIMEOUT_US_1MS		1000

#define RESET_CELL(_scmi_id, _id, _name) \
	[_scmi_id] = { \
		.reset_id = _id, \
		.name = _name, \
	}

struct stm32_scmi_rd {
	unsigned long reset_id;
	const char *name;
};

/* Locate all non-secure SMT message buffers in last page of SYSRAM */
#define SMT_BUFFER_BASE		CFG_STM32MP1_SCMI_SHM_BASE
#define SMT_BUFFER0_BASE	SMT_BUFFER_BASE
#define SMT_BUFFER1_BASE	(SMT_BUFFER_BASE + 0x200)
#define SMT_BUFFER_END		(SMT_BUFFER1_BASE + SMT_BUF_SLOT_SIZE)

#if SMT_BUFFER_END > (CFG_STM32MP1_SCMI_SHM_BASE + CFG_STM32MP1_SCMI_SHM_SIZE)
#error "SCMI shared memory mismatch"
#endif

register_phys_mem(MEM_AREA_IO_NSEC, CFG_STM32MP1_SCMI_SHM_BASE,
		  CFG_STM32MP1_SCMI_SHM_SIZE);

static struct scmi_msg_channel scmi_channel[] = {
	[0] = {
		/* Virtual address ::shm_addr is computed at init */
		.agent_name = "stm32mp1-clock",
		.shm_addr = { .pa = SMT_BUFFER0_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
	[1] = {
		/* Virtual address ::shm_addr is computed at init */
		.agent_name = "stm32mp1-reset",
		.shm_addr = { .pa = SMT_BUFFER1_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
};

struct scmi_msg_channel *plat_scmi_get_channel(unsigned int agent_id)
{
	assert(agent_id < ARRAY_SIZE(scmi_channel));

	return &scmi_channel[agent_id];
}

struct stm32_scmi_rd stm32_scmi_reset_domain[] = {
	RESET_CELL(RST_SCMI_SPI6, SPI6_R, "spi6"),
	RESET_CELL(RST_SCMI_I2C4, I2C4_R, "i2c4"),
	RESET_CELL(RST_SCMI_I2C6, I2C6_R, "i2c6"),
	RESET_CELL(RST_SCMI_USART1, USART1_R, "usart1"),
	RESET_CELL(RST_SCMI_STGEN, STGEN_R, "stgen"),
	RESET_CELL(RST_SCMI_GPIOZ, GPIOZ_R, "gpioz"),
	RESET_CELL(RST_SCMI_CRYP1, CRYP1_R, "cryp1"),
	RESET_CELL(RST_SCMI_HASH1, HASH1_R, "hash1"),
	RESET_CELL(RST_SCMI_RNG1, RNG1_R, "rng1"),
	RESET_CELL(RST_SCMI_MDMA, MDMA_R, "mdma"),
	RESET_CELL(RST_SCMI_MCU, MCU_R, "mcu"),
};

struct scmi_agent_resources {
	struct stm32_scmi_clk *clock;
	size_t clock_count;
	struct stm32_scmi_rd *rd;
	size_t rd_count;
	struct stm32_scmi_pd *pd;
	size_t pd_count;
	struct stm32_scmi_perfs *perfs;
	size_t perfs_count;
};

const struct scmi_agent_resources agent_resources[] = {
	[1] = {
		.rd = stm32_scmi_reset_domain,
		.rd_count = ARRAY_SIZE(stm32_scmi_reset_domain),
	},
};

static const struct scmi_agent_resources *find_resource(unsigned int agent_id)
{
	assert(agent_id < ARRAY_SIZE(agent_resources));

	return &agent_resources[agent_id];
}

static size_t __maybe_unused plat_scmi_protocol_count_paranoid(void)
{
	unsigned int n = 0;
	unsigned int count = 0;
	const size_t nb_elts = ARRAY_SIZE(agent_resources);

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].clock_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].rd_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].pd_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].perfs_count)
			break;
	if (n < nb_elts)
		count++;

	return count;
}

static const char vendor[] = "ST";
static const char sub_vendor[] = "";

const char *plat_scmi_vendor_name(void)
{
	return vendor;
}

const char *plat_scmi_sub_vendor_name(void)
{
	return sub_vendor;
}

/* Currently supporting Reset Domains */
static const uint8_t plat_protocol_list[] = {
	SCMI_PROTOCOL_ID_RESET_DOMAIN,
	0 /* Null termination */
};

size_t plat_scmi_protocol_count(void)
{
	const size_t count = ARRAY_SIZE(plat_protocol_list) - 1;

	assert(count == plat_scmi_protocol_count_paranoid());

	return count;
}

const uint8_t *plat_scmi_protocol_list(unsigned int agent_id __unused)
{

	assert(plat_scmi_protocol_count_paranoid() ==
	       (ARRAY_SIZE(plat_protocol_list) - 1));

	return plat_protocol_list;
}

/*
 * Platform SCMI reset domains
 */
static struct stm32_scmi_rd *find_rd(unsigned int agent_id,
				     unsigned int scmi_id)
{
	const struct scmi_agent_resources *resource = find_resource(agent_id);
	struct stm32_scmi_rd *reset = NULL;
	size_t n = 0;

	if (!resource || !resource->rd_count)
		goto out;

	for (n = 0; n < resource->rd_count; n++)
		if (n == scmi_id)
			break;

	if (n < resource->rd_count) {
		reset = &resource->rd[n];
		if (!reset->name ||
		    !stm32mp_nsec_can_access_reset(reset->reset_id))
			reset = NULL;
	}

out:
	return reset;
}

const char *plat_scmi_rd_get_name(unsigned int agent_id, unsigned int scmi_id)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return NULL;

	return rd->name;
}

size_t plat_scmi_rd_count(unsigned int agent_id)
{
	const struct scmi_agent_resources *res = find_resource(agent_id);

	if (!res)
		return 0;

	return res->rd_count;
}

int32_t plat_scmi_rd_autonomous(unsigned int agent_id, unsigned int scmi_id,
				uint32_t state)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	/* Supports only full reset with context loss */
	if (state)
		return SCMI_NOT_SUPPORTED;

	DMSG("SCMI reset %u cycle", scmi_id);

	if (stm32_reset_assert_to(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	if (stm32_reset_deassert_to(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	return SCMI_SUCCESS;
}

int32_t plat_scmi_rd_set_state(unsigned int agent_id, unsigned int scmi_id,
			       bool assert_not_deassert)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	if (assert_not_deassert) {
		DMSG("SCMI reset %u assert", scmi_id);
		stm32_reset_set(rd->reset_id);
	} else {
		DMSG("SCMI reset %u deassert", scmi_id);
		stm32_reset_release(rd->reset_id);
	}

	return SCMI_SUCCESS;
}

/*
 * Initialize platform SCMI resources
 */
static TEE_Result stm32mp1_init_scmi_server(void)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(scmi_channel); i++) {
		struct scmi_msg_channel *chan = &scmi_channel[i];

		chan->shm_addr.va = (vaddr_t)phys_to_virt(chan->shm_addr.pa,
							  MEM_AREA_IO_NSEC);
		assert(chan->shm_addr.va);

		scmi_smt_init_agent_channel(chan);
	}

	return TEE_SUCCESS;
}

driver_init_late(stm32mp1_init_scmi_server);
