// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */
#include <crypto/crypto.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>

#define TA_NAME		"interrupt_tests.ta"

#define INTERRUPT_TESTS_UUID \
		{ 0x48d58475, 0x3d5e, 0x4202, \
		{ 0xa7, 0x75, 0x97, 0x85, 0xd2, 0x0f, 0x78, 0xae } }

#define CMD_INTERRUPT_TESTS	0

#define SGI_NUM		16
#define PPI_NUM		32

#ifndef TEST_SGI_ID
#define TEST_SGI_ID	11
#endif
#ifndef TEST_PPI_ID
#define TEST_PPI_ID	29
#endif
#ifndef TEST_SPI_ID
#define TEST_SPI_ID	61
#endif
#ifndef TEST_TIMES
#define TEST_TIMES	3
#endif

/*
 * Trusted Application Entry Points
 */

static size_t test_sgi_value[CFG_TEE_CORE_NB_CORE];
static size_t test_spi_value[CFG_TEE_CORE_NB_CORE];
static size_t test_ppi_value[CFG_TEE_CORE_NB_CORE];
static size_t expect_sgi_value[CFG_TEE_CORE_NB_CORE];
static size_t expect_spi_value[CFG_TEE_CORE_NB_CORE];
static size_t expect_ppi_value[CFG_TEE_CORE_NB_CORE];

static enum itr_return __maybe_unused ihandler_ok(struct itr_handler *handler)
{
	size_t core_num = get_core_pos();

	assert(core_num < CFG_TEE_CORE_NB_CORE);

	if (handler->it < SGI_NUM)
		test_sgi_value[core_num]++;
	else if (handler->it < PPI_NUM)
		test_ppi_value[core_num]++;
	else
		test_spi_value[core_num]++;

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(ihandler_ok);

struct itr_handler sgi_handler = {
	.it = TEST_SGI_ID,
	.handler = ihandler_ok,
};

struct itr_handler spi_handler = {
	.it = TEST_SPI_ID,
	.handler = ihandler_ok,
};

struct itr_handler ppi_handler = {
	.it = TEST_PPI_ID,
	.handler = ihandler_ok,
};

static TEE_Result test_sgi(void)
{
	TEE_Result res;
	uint8_t i;
	uint8_t j;
	uint8_t num;
	uint8_t cpu_mask;

	itr_add(&sgi_handler);
	itr_enable(TEST_SGI_ID);

	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
		expect_sgi_value[i]++;
	itr_raise_sgi(TEST_SGI_ID,
		     (uint8_t)(SHIFT_U32(1, CFG_TEE_CORE_NB_CORE) - 1));
	tee_time_wait(200);
	if (memcmp(test_sgi_value, expect_sgi_value, sizeof(test_sgi_value)))
		return TEE_ERROR_GENERIC;

	for (i = 0; i < TEST_TIMES; i++) {
		res = crypto_rng_read(&num, 1);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_GENERIC;
		num = num % CFG_TEE_CORE_NB_CORE;
		cpu_mask = 0x0;
		for (j = 0; j < num; j++) {
			expect_sgi_value[j]++;
			cpu_mask |= (0x1 << j);
		}
		itr_raise_sgi(TEST_SGI_ID, cpu_mask);
		tee_time_wait(200);
		if (memcmp(test_sgi_value, expect_sgi_value,
		    sizeof(test_sgi_value)))
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result test_spi(void)
{
	TEE_Result res;
	uint8_t i;
	uint8_t num;

	itr_add(&spi_handler);
	itr_enable(TEST_SPI_ID);

	for (i = 0; i < TEST_TIMES; i++) {
		res = crypto_rng_read(&num, 1);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_GENERIC;
		num = num % CFG_TEE_CORE_NB_CORE;
		expect_spi_value[num]++;
		itr_set_affinity(TEST_SPI_ID, 0x1 << num);
		itr_raise_pi(TEST_SPI_ID);
		tee_time_wait(200);
		if (memcmp(test_spi_value, expect_spi_value,
		    sizeof(test_spi_value)))
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result test_ppi(void)
{
	uint32_t exceptions;

	itr_add(&ppi_handler);
	itr_enable(TEST_PPI_ID);

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	expect_ppi_value[get_core_pos()]++;
	itr_raise_pi(TEST_PPI_ID);
	thread_unmask_exceptions(exceptions);
	tee_time_wait(200);
	if (memcmp(test_ppi_value, expect_ppi_value, sizeof(test_ppi_value)))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result interrupt_tests(uint32_t nParamTypes __unused,
			TEE_Param pParams[TEE_NUM_PARAMS]__unused)
{
	TEE_Result res;

	res = test_sgi();
	if (res != TEE_SUCCESS)
		return res;

	res = test_spi();
	if (res != TEE_SUCCESS)
		return res;

	res = test_ppi();
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{
	TEE_Result res;
	uint8_t i;

	switch (cmd) {
	case CMD_INTERRUPT_TESTS:
		res = interrupt_tests(ptypes, params);
		DMSG("test value: sgi spi ppi");
		for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
			DMSG("------------[%zu] [%zu] [%zu]",
			    test_sgi_value[i], test_spi_value[i],
			    test_ppi_value[i]);
		DMSG("expc value: sgi spi ppi");
		for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
			DMSG("------------[%zu] [%zu] [%zu]",
			    expect_sgi_value[i], expect_spi_value[i],
			    expect_ppi_value[i]);
		return res;
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = INTERRUPT_TESTS_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
