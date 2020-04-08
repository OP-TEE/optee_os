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
#include <speculation_barrier.h>
#include <stm32_util.h>
#include <string.h>
#include <tee_api_defines.h>
#include <util.h>

#define TIMEOUT_US_1MS		1000

#define SCMI_RD_NAME_SIZE	16

/*
 * struct stm32_scmi_rd - Data for the exposed reset controller
 * @reset_id: Reset identifier in RCC reset driver
 * @name: Reset string ID exposed to agent
 */
struct stm32_scmi_rd {
	unsigned long reset_id;
	const char *name;
};

/* Locate all non-secure SMT message buffers in last page of SYSRAM */
#define SMT_BUFFER_BASE		CFG_STM32MP1_SCMI_SHM_BASE
#define SMT_BUFFER0_BASE	SMT_BUFFER_BASE
#define SMT_BUFFER1_BASE	(SMT_BUFFER_BASE + 0x200)

#if (SMT_BUFFER1_BASE + SMT_BUF_SLOT_SIZE > \
	CFG_STM32MP1_SCMI_SHM_BASE + CFG_STM32MP1_SCMI_SHM_SIZE)
#error "SCMI shared memory mismatch"
#endif

register_phys_mem(MEM_AREA_IO_NSEC, CFG_STM32MP1_SCMI_SHM_BASE,
		  CFG_STM32MP1_SCMI_SHM_SIZE);

static struct scmi_msg_channel scmi_channel[] = {
	[0] = {
		.agent_name = "stm32mp1-agent-0",
		.shm_addr = { .pa = SMT_BUFFER0_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
	[1] = {
		.agent_name = "stm32mp1-agent-1",
		.shm_addr =  { .pa = SMT_BUFFER1_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
};

struct scmi_msg_channel *plat_scmi_get_channel(unsigned int agent_id)
{
	assert(agent_id < ARRAY_SIZE(scmi_channel));

	return &scmi_channel[agent_id];
}

#define RESET_CELL(_scmi_id, _id, _name) \
	[_scmi_id] = { \
		.reset_id = _id, \
		.name = _name, \
	}

struct stm32_scmi_rd stm32_scmi0_reset_domain[] = {
	RESET_CELL(RST_SCMI0_SPI6, SPI6_R, "spi6"),
	RESET_CELL(RST_SCMI0_I2C4, I2C4_R, "i2c4"),
	RESET_CELL(RST_SCMI0_I2C6, I2C6_R, "i2c6"),
	RESET_CELL(RST_SCMI0_USART1, USART1_R, "usart1"),
	RESET_CELL(RST_SCMI0_STGEN, STGEN_R, "stgen"),
	RESET_CELL(RST_SCMI0_GPIOZ, GPIOZ_R, "gpioz"),
	RESET_CELL(RST_SCMI0_CRYP1, CRYP1_R, "cryp1"),
	RESET_CELL(RST_SCMI0_HASH1, HASH1_R, "hash1"),
	RESET_CELL(RST_SCMI0_RNG1, RNG1_R, "rng1"),
	RESET_CELL(RST_SCMI0_MDMA, MDMA_R, "mdma"),
	RESET_CELL(RST_SCMI0_MCU, MCU_R, "mcu"),
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
	[0] = {
		.rd = stm32_scmi0_reset_domain,
		.rd_count = ARRAY_SIZE(stm32_scmi0_reset_domain),
	},
	[1] = { },
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
	const size_t agent_count = ARRAY_SIZE(agent_resources);

	for (n = 0; n < agent_count; n++)
		if (agent_resources[n].clock_count)
			break;
	if (n < agent_count)
		count++;

	for (n = 0; n < agent_count; n++)
		if (agent_resources[n].rd_count)
			break;
	if (n < agent_count)
		count++;

	for (n = 0; n < agent_count; n++)
		if (agent_resources[n].pd_count)
			break;
	if (n < agent_count)
		count++;

	for (n = 0; n < agent_count; n++)
		if (agent_resources[n].perfs_count)
			break;
	if (n < agent_count)
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
	size_t n = 0;

	if (resource) {
		for (n = 0; n < resource->rd_count; n++)
			if (n == scmi_id)
				return &resource->rd[n];
	}

	return NULL;
}

const char *plat_scmi_rd_get_name(unsigned int agent_id, unsigned int scmi_id)
{
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return NULL;

	return rd->name;
}

size_t plat_scmi_rd_count(unsigned int agent_id)
{
	const struct scmi_agent_resources *resource = find_resource(agent_id);

	if (!resource)
		return 0;

	return resource->rd_count;
}

int32_t plat_scmi_rd_autonomous(unsigned int agent_id, unsigned int scmi_id,
				uint32_t state)
{
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	if (!stm32mp_nsec_can_access_reset(rd->reset_id))
		return SCMI_DENIED;

	/* Supports only reset with context loss */
	if (state)
		return SCMI_NOT_SUPPORTED;

	DMSG("SCMI reset %u cycle", scmi_id);

	if (stm32_reset_assert(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	if (stm32_reset_deassert(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	return SCMI_SUCCESS;
}

int32_t plat_scmi_rd_set_state(unsigned int agent_id, unsigned int scmi_id,
			       bool assert_not_deassert)
{
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	if (!stm32mp_nsec_can_access_reset(rd->reset_id))
		return SCMI_DENIED;

	if (assert_not_deassert) {
		DMSG("SCMI reset %u set", scmi_id);
		stm32_reset_set(rd->reset_id);
	} else {
		DMSG("SCMI reset %u release", scmi_id);
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
	size_t j = 0;

	for (i = 0; i < ARRAY_SIZE(scmi_channel); i++) {
		struct scmi_msg_channel *chan = &scmi_channel[i];

		/* Enforce non-secure shm mapped as device memory */
		chan->shm_addr.va = (vaddr_t)phys_to_virt(chan->shm_addr.pa,
							  MEM_AREA_IO_NSEC);
		assert(chan->shm_addr.va);

		scmi_smt_init_agent_channel(chan);
	}

	for (i = 0; i < ARRAY_SIZE(agent_resources); i++) {
		const struct scmi_agent_resources *res = &agent_resources[i];

		for (j = 0; j < res->rd_count; j++) {
			struct stm32_scmi_rd *rd = &res->rd[j];

			if (!rd->name ||
			    strlen(rd->name) >= SCMI_RD_NAME_SIZE)
				panic("SCMI reset domain name invalid");
		}
	}

	return TEE_SUCCESS;
}

driver_init_late(stm32mp1_init_scmi_server);
