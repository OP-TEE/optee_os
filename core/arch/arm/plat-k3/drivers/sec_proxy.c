// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 Secure Proxy Driver
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

#include "sec_proxy.h"

/* SEC PROXY RT THREAD STATUS */
#define RT_THREAD_STATUS_REG            0x0
#define RT_THREAD_STATUS_ERROR_MASK     BIT(31)
#define RT_THREAD_STATUS_CUR_CNT_MASK   GENMASK_32(7, 0)

/* SEC PROXY SCFG THREAD CTRL */
#define SCFG_THREAD_CTRL_REG            0x1000
#define SCFG_THREAD_CTRL_DIR_SHIFT      31
#define SCFG_THREAD_CTRL_DIR_MASK       BIT(31)

/* SECURE PROXY GENERIC HELPERS */
enum threads {
	SEC_PROXY_TX_THREAD,
	SEC_PROXY_RX_THREAD,
	SEC_PROXY_MAX_THREADS
};

#define SEC_PROXY_THREAD(base, x)       ((base) + (0x1000 * (x)))
#define SEC_PROXY_DATA_START_OFFS       0x4
#define SEC_PROXY_DATA_END_OFFS         0x3c

#define THREAD_DIR_TX (0)
#define THREAD_DIR_RX (1)

/**
 * struct k3_sec_proxy_thread - Description of a Secure Proxy Thread
 * @id:		Thread ID
 * @data:	Thread Data path region for target
 * @scfg:	Secure Config Region for Thread
 * @rt:		RealTime Region for Thread
 */
struct k3_sec_proxy_thread {
	const char *name;
	vaddr_t data;
	vaddr_t scfg;
	vaddr_t rt;
} spts[SEC_PROXY_MAX_THREADS];

/**
 * k3_sec_proxy_verify_thread() - Verify thread status before
 *				  sending/receiving data
 * @dir: Direction of the thread
 */
static TEE_Result k3_sec_proxy_verify_thread(uint32_t dir)
{
	struct k3_sec_proxy_thread *spt = &spts[dir];
	uint64_t timeout = 0;
	uint32_t val = 0;
	unsigned int retry = 2;

	FMSG("Check for thread corruption");
	val = io_read32(spt->rt + RT_THREAD_STATUS_REG);

	/* Check for any errors already available */
	while ((val & RT_THREAD_STATUS_ERROR_MASK) && retry--) {
		if (!retry) {
			EMSG("Thread %s is corrupted, cannot send data.",
			     spt->name);
			return TEE_ERROR_BAD_STATE;
		}

		/* Write Bit 0 to this location */
		IMSG("Resetting proxy thread %s", spt->name);
		val ^= RT_THREAD_STATUS_ERROR_MASK;
		io_write32(spt->rt + RT_THREAD_STATUS_REG, val);
	}

	FMSG("Check for thread direction");
	/* Make sure thread is configured for right direction */
	if ((io_read32(spt->scfg + SCFG_THREAD_CTRL_REG) &
	     SCFG_THREAD_CTRL_DIR_MASK) >> SCFG_THREAD_CTRL_DIR_SHIFT != dir) {
		if (dir == SEC_PROXY_TX_THREAD)
			EMSG("Trying to receive data on tx Thread %s",
			     spt->name);
		else
			EMSG("Trying to send data on rx Thread %s", spt->name);
		return TEE_ERROR_COMMUNICATION;
	}

	FMSG("Check for thread queue");
	/* Check the message queue before sending/receiving data */
	timeout = timeout_init_us(SEC_PROXY_TIMEOUT_US);
	while (!(io_read32(spt->rt + RT_THREAD_STATUS_REG) &
		 RT_THREAD_STATUS_CUR_CNT_MASK)) {
		DMSG("Waiting for thread %s to %s", spt->name,
		     (dir == THREAD_DIR_TX) ? "empty" : "fill");
		if (timeout_elapsed(timeout)) {
			EMSG("Queue is busy");
			return TEE_ERROR_BUSY;
		}
	}

	FMSG("Success");
	return TEE_SUCCESS;
}

/**
 * k3_sec_proxy_send() - Send data over a Secure Proxy thread
 * @msg: Pointer to k3_sec_proxy_msg
 */
TEE_Result k3_sec_proxy_send(const struct k3_sec_proxy_msg *msg)
{
	struct k3_sec_proxy_thread *spt = &spts[SEC_PROXY_TX_THREAD];
	int num_words = 0;
	int trail_bytes = 0;
	int i = 0;
	uintptr_t data_reg = 0;
	uint32_t data_word = 0;
	TEE_Result ret = TEE_SUCCESS;

	FMSG("Verifying the thread");
	ret = k3_sec_proxy_verify_thread(THREAD_DIR_TX);
	if (ret) {
		EMSG("Thread %s verification failed. ret = %d", spt->name, ret);
		return ret;
	}

	/* Check the message size. */
	if (msg->len > SEC_PROXY_MAX_MSG_SIZE) {
		EMSG("Thread %s message length %zu > max msg size %d",
		     spt->name, msg->len, SEC_PROXY_MAX_MSG_SIZE);
		return TEE_ERROR_BAD_STATE;
	}

	/* Send the message */
	data_reg = spt->data + SEC_PROXY_DATA_START_OFFS;
	num_words = msg->len / sizeof(uint32_t);
	for (i = 0; i < num_words; i++) {
		memcpy(&data_word, &msg->buf[i * 4], sizeof(uint32_t));
		io_write32(data_reg, data_word);
		data_reg += sizeof(uint32_t);
	}

	trail_bytes = msg->len % sizeof(uint32_t);
	if (trail_bytes) {
		uint32_t data_trail = 0;

		i = msg->len - trail_bytes;
		while (trail_bytes--) {
			data_trail <<= 8;
			data_trail |= msg->buf[i++];
		}

		io_write32(data_reg, data_trail);
		data_reg += sizeof(uint32_t);
	}

	/*
	 * 'data_reg' indicates next register to write. If we did not already
	 * write on tx complete reg(last reg), we must do so for transmit
	 */
	if (data_reg <= (spt->data + SEC_PROXY_DATA_END_OFFS))
		io_write32(spt->data + SEC_PROXY_DATA_END_OFFS, 0);

	return TEE_SUCCESS;
}

/**
 * k3_sec_proxy_recv() - Receive data from a Secure Proxy thread
 * @msg: Pointer to k3_sec_proxy_msg
 */
TEE_Result k3_sec_proxy_recv(struct k3_sec_proxy_msg *msg)
{
	struct k3_sec_proxy_thread *spt = &spts[SEC_PROXY_RX_THREAD];
	int num_words = 0;
	int i = 0;
	int trail_bytes = 0;
	uint32_t data_trail = 0;
	uint32_t data_word = 0;
	uintptr_t data_reg = 0;
	TEE_Result ret = TEE_SUCCESS;

	FMSG("Verifying thread");
	ret = k3_sec_proxy_verify_thread(THREAD_DIR_RX);
	if (ret) {
		EMSG("Thread %s verification failed. ret = %d", spt->name, ret);
		return ret;
	}

	/* Receive the message */
	data_reg = spt->data + SEC_PROXY_DATA_START_OFFS;
	num_words = msg->len / sizeof(uint32_t);
	for (i = 0; i < num_words; i++) {
		data_word = io_read32(data_reg);
		memcpy(&msg->buf[i * 4], &data_word, sizeof(uint32_t));
		data_reg += sizeof(uint32_t);
	}

	trail_bytes = msg->len % sizeof(uint32_t);
	if (trail_bytes) {
		data_trail = io_read32(data_reg);
		data_reg += sizeof(uint32_t);

		i = msg->len - trail_bytes;
		while (trail_bytes--) {
			msg->buf[i++] = data_trail & 0xff;
			data_trail >>= 8;
		}
	}

	/*
	 * 'data_reg' indicates next register to read. If we did not already
	 * read on rx complete reg(last reg), we must do so for receive
	 */
	if (data_reg <= (spt->data + SEC_PROXY_DATA_END_OFFS))
		io_read32(spt->data + SEC_PROXY_DATA_END_OFFS);

	return TEE_SUCCESS;
}

/**
 * k3_sec_proxy_init() - Initialize the secure proxy threads
 */
TEE_Result k3_sec_proxy_init(void)
{
	struct k3_sec_proxy_thread *thread;
	int rx_thread = SEC_PROXY_RESPONSE_THREAD;
	int tx_thread = SEC_PROXY_REQUEST_THREAD;
	uint32_t target_data = 0;
	uint32_t cfg_scfg = 0;
	uint32_t cfg_rt = 0;

	DMSG("tx_thread: %d, rx_thread: %d", tx_thread, rx_thread);

	/* TX_THREAD */
	target_data = SEC_PROXY_THREAD(SEC_PROXY_DATA_BASE, tx_thread);
	cfg_scfg = SEC_PROXY_THREAD(SEC_PROXY_SCFG_BASE, tx_thread);
	cfg_rt = SEC_PROXY_THREAD(SEC_PROXY_RT_BASE, tx_thread);

	thread = &spts[SEC_PROXY_TX_THREAD];
	thread->name = "SEC_PROXY_LOW_PRIORITY_THREAD";

	thread->data = core_mmu_get_va(target_data, MEM_AREA_IO_SEC,
				       SEC_PROXY_DATA_SIZE);
	if (!thread->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	thread->scfg = core_mmu_get_va(cfg_scfg, MEM_AREA_IO_SEC,
				       SEC_PROXY_SCFG_SIZE);
	if (!thread->scfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	thread->rt = core_mmu_get_va(cfg_rt, MEM_AREA_IO_SEC,
				     SEC_PROXY_RT_SIZE);
	if (!thread->rt)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* RX_THREAD */
	target_data = SEC_PROXY_THREAD(SEC_PROXY_DATA_BASE, rx_thread);
	cfg_scfg = SEC_PROXY_THREAD(SEC_PROXY_SCFG_BASE, rx_thread);
	cfg_rt = SEC_PROXY_THREAD(SEC_PROXY_RT_BASE, rx_thread);

	thread = &spts[SEC_PROXY_RX_THREAD];
	thread->name = "SEC_PROXY_RESPONSE_THREAD";

	thread->data = core_mmu_get_va(target_data, MEM_AREA_IO_SEC,
				       SEC_PROXY_DATA_SIZE);
	if (!thread->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	thread->scfg = core_mmu_get_va(cfg_scfg, MEM_AREA_IO_SEC,
				       SEC_PROXY_SCFG_SIZE);
	if (!thread->scfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	thread->rt = core_mmu_get_va(cfg_rt, MEM_AREA_IO_SEC,
				     SEC_PROXY_RT_SIZE);
	if (!thread->rt)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}
