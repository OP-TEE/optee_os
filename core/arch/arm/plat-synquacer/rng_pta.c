// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018-2022, Linaro Limited
 */

/*
 * Developerbox doesn't provide a hardware based true random number
 * generator. So this pseudo TA provides a good source of entropy using
 * noise from 7 thermal sensors. Its suitable for entropy required
 * during boot, seeding kernel entropy pool, cryptographic use etc.
 *
 * Assumption
 * ==========
 *
 * We have assumed the entropy of the sensor is better than 8 bits per
 * 14 sensor readings. This entropy estimate is based on our simple
 * minimal entropy estimates done on 2.1G bytes of raw samples collected
 * from thermal sensors.
 *
 * We believe our estimate to be conservative and have designed to
 * health tests to trigger if a sensor does not achieve at least
 * 8 bits in 16 sensor reading (we use 16 rather than 14 to prevent
 * spurious failures on edge cases).
 *
 * Theory of operation
 * ===================
 *
 * This routine uses secure timer interrupt to sample raw thermal sensor
 * readings. As thermal sensor refresh rate is every 2ms, so interrupt
 * fires every 2ms. It implements continuous health test counting rising
 * and falling edges to report if sensors fail to provide entropy.
 *
 * It uses vetted conditioner as SHA512/256 (approved hash algorithm)
 * to condense entropy. As per NIST.SP.800-90B spec, to get full entropy
 * from vetted conditioner, we need to supply double of input entropy.
 * According to assumption above and requirement for vetted conditioner,
 * we need to supply 28 raw sensor readings to get 1 byte of full
 * entropy as output. So for 32 bytes of conditioner output, we need to
 * supply 896 bytes of raw sensor readings.
 *
 * Interfaces -> Input
 * -------------------
 *
 * void rng_collect_entropy(void);
 *
 * Called as part of secure timer interrupt handler to sample raw
 * thermal sensor readings and add entropy to the pool.
 *
 * Interfaces -> Output
 * --------------------
 *
 * TEE_Result rng_get_entropy(uint32_t types,
 *                            TEE_Param params[TEE_NUM_PARAMS]);
 *
 * Invoke command to expose an entropy interface to normal world.
 *
 * Testing
 * =======
 *
 * Passes FIPS 140-2 rngtest.
 *
 * Limitations
 * ===========
 *
 * Output rate is limited to approx. 125 bytes per second.
 *
 * Our entropy estimation was not reached using any approved or
 * published estimation framework such as NIST.SP.800-90B and was tested
 * on a very small set of physical samples. Instead we have adopted what
 * we believe to be a conservative estimate and partnered it with a
 * fairly agressive health check.
 *
 * Generating the SHA512/256 hash takes 24uS and will be run by an
 * interrupt handler that pre-empts the normal world.
 */

#include <crypto/crypto.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <io.h>
#include <pta_rng.h>
#include <string.h>

#include "synquacer_rng_pta.h"

#define PTA_NAME "rng.pta"

#define THERMAL_SENSOR_BASE0		0x54190800
#define THERMAL_SENSOR_OFFSET		0x80
#define NUM_SENSORS			7
#define NUM_SLOTS			((NUM_SENSORS * 2) - 1)

#define TEMP_DATA_REG_OFFSET		0x34

#define ENTROPY_POOL_SIZE		4096

#define SENSOR_DATA_SIZE		128
#define CONDITIONER_PAYLOAD		(SENSOR_DATA_SIZE * NUM_SENSORS)

/*
 * The health test monitors each sensor's least significant bit and counts
 * the number of rising and falling edges. It verifies that both counts
 * lie within interval of between 12.5% and 37.5% of the samples.
 * For true random data with 8 bits of entropy per byte, both counts would
 * be close to 25%.
 */
#define MAX_BIT_FLIP_EDGE_COUNT		((3 * SENSOR_DATA_SIZE) / 8)
#define MIN_BIT_FLIP_EDGE_COUNT		(SENSOR_DATA_SIZE / 8)

static uint8_t entropy_pool[ENTROPY_POOL_SIZE] = {0};
static uint32_t entropy_size;

static uint8_t sensors_data[NUM_SLOTS][SENSOR_DATA_SIZE] = {0};
static uint8_t sensors_data_slot_idx;
static uint8_t sensors_data_idx;

static uint32_t health_test_fail_cnt;
static uint32_t health_test_cnt;

static unsigned int entropy_lock = SPINLOCK_UNLOCK;

static void pool_add_entropy(uint8_t *entropy, uint32_t size)
{
	uint32_t copy_size;

	if (entropy_size >= ENTROPY_POOL_SIZE)
		return;

	if ((ENTROPY_POOL_SIZE - entropy_size) >= size)
		copy_size = size;
	else
		copy_size = ENTROPY_POOL_SIZE - entropy_size;

	memcpy((entropy_pool + entropy_size), entropy, copy_size);

	entropy_size += copy_size;
}

static void pool_get_entropy(uint8_t *buf, uint32_t size)
{
	uint32_t off;

	if (size > entropy_size)
		return;

	off = entropy_size - size;

	memcpy(buf, &entropy_pool[off], size);
	entropy_size -= size;
}

static bool health_test(uint8_t sensor_id)
{
	uint32_t falling_edge_count = 0, rising_edge_count = 0;
	uint32_t lo_edge_count, hi_edge_count;
	uint32_t i;

	for (i = 0; i < (SENSOR_DATA_SIZE - 1); i++) {
		if ((sensors_data[sensor_id][i] ^
		     sensors_data[sensor_id][i + 1]) & 0x1) {
			falling_edge_count += (sensors_data[sensor_id][i] &
					       0x1);
			rising_edge_count += (sensors_data[sensor_id][i + 1] &
					      0x1);
		}
	}

	lo_edge_count = rising_edge_count < falling_edge_count ?
			rising_edge_count : falling_edge_count;
	hi_edge_count = rising_edge_count < falling_edge_count ?
			falling_edge_count : rising_edge_count;

	return (lo_edge_count >= MIN_BIT_FLIP_EDGE_COUNT) &&
	       (hi_edge_count <= MAX_BIT_FLIP_EDGE_COUNT);
}

static uint8_t pool_check_add_entropy(void)
{
	uint32_t i;
	uint8_t entropy_sha512_256[TEE_SHA256_HASH_SIZE];
	uint8_t pool_status = 0;
	TEE_Result res;

	for (i = 0; i < NUM_SENSORS; i++) {
		/* Check if particular sensor data passes health test */
		if (health_test(sensors_data_slot_idx) == true) {
			sensors_data_slot_idx++;
		} else {
			health_test_fail_cnt++;
			memmove(sensors_data[sensors_data_slot_idx],
				sensors_data[sensors_data_slot_idx + 1],
				(SENSOR_DATA_SIZE * (NUM_SENSORS - i - 1)));
		}
	}

	health_test_cnt += NUM_SENSORS;

	/* Check if sensors_data have enough pass data for conditioning */
	if (sensors_data_slot_idx >= NUM_SENSORS) {
		/*
		 * Use vetted conditioner SHA512/256 as per
		 * NIST.SP.800-90B to condition raw data from entropy
		 * source.
		 */
		sensors_data_slot_idx -= NUM_SENSORS;
		res = hash_sha512_256_compute(entropy_sha512_256,
					sensors_data[sensors_data_slot_idx],
					CONDITIONER_PAYLOAD);
		if (res == TEE_SUCCESS)
			pool_add_entropy(entropy_sha512_256,
					 TEE_SHA256_HASH_SIZE);
	}

	if (entropy_size >= ENTROPY_POOL_SIZE)
		pool_status = 1;

	return pool_status;
}

void rng_collect_entropy(void)
{
	uint8_t i, pool_full = 0;
	void *vaddr;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(&entropy_lock);

	for (i = 0; i < NUM_SENSORS; i++) {
		vaddr = phys_to_virt_io(THERMAL_SENSOR_BASE0 +
					(THERMAL_SENSOR_OFFSET * i) +
					TEMP_DATA_REG_OFFSET,
					sizeof(uint32_t));
		sensors_data[sensors_data_slot_idx + i][sensors_data_idx] =
					(uint8_t)io_read32((vaddr_t)vaddr);
	}

	sensors_data_idx++;

	if (sensors_data_idx >= SENSOR_DATA_SIZE) {
		pool_full = pool_check_add_entropy();
		sensors_data_idx = 0;
	}

	if (pool_full)
		generic_timer_stop();

	cpu_spin_unlock(&entropy_lock);
	thread_set_exceptions(exceptions);
}

static TEE_Result rng_get_entropy(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *e = NULL;
	uint32_t pool_size = 0, rq_size = 0;
	uint32_t exceptions;
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rq_size = params[0].memref.size;

	if ((rq_size == 0) || (rq_size > ENTROPY_POOL_SIZE))
		return TEE_ERROR_NOT_SUPPORTED;

	e = (uint8_t *)params[0].memref.buffer;
	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&entropy_lock);

	/*
	 * Report health test failure to normal world in case fail count
	 * exceeds 1% of pass count.
	 */
	if (health_test_fail_cnt > ((health_test_cnt + 100) / 100)) {
		res = TEE_ERROR_HEALTH_TEST_FAIL;
		params[0].memref.size = 0;
		health_test_cnt = 0;
		health_test_fail_cnt = 0;
		goto exit;
	}

	pool_size = entropy_size;

	if (pool_size < rq_size) {
		params[0].memref.size = pool_size;
		pool_get_entropy(e, pool_size);
	} else {
		params[0].memref.size = rq_size;
		pool_get_entropy(e, rq_size);
	}

exit:
	/* Enable timer FIQ to fetch entropy */
	generic_timer_start(TIMER_PERIOD_MS);

	cpu_spin_unlock(&entropy_lock);
	thread_set_exceptions(exceptions);

	return res;
}

static TEE_Result rng_get_info(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Output RNG rate (per second) */
	params[0].value.a = 125;

	/*
	 * Quality/entropy per 1024 bit of output data. As we have used
	 * a vetted conditioner as per NIST.SP.800-90B to provide full
	 * entropy given our assumption of entropy estimate for raw sensor
	 * data.
	 */
	params[0].value.b = 1024;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_GET_ENTROPY:
		return rng_get_entropy(nParamTypes, pParams);
	case PTA_CMD_GET_RNG_INFO:
		return rng_get_info(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_RNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
