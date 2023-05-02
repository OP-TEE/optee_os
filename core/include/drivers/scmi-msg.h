/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019-2021, Linaro Limited
 */

#ifndef SCMI_MSG_H
#define SCMI_MSG_H

#include <compiler.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Minimum size expected for SMT based shared memory message buffers */
#define SMT_BUF_SLOT_SIZE	U(128)

/* Standard values for SCMI voltage domain protocol configuration state */
#define SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_ON	U(0x7)
#define SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_OFF	U(0)

/* A channel abstract a communication path between agent and server */
struct scmi_msg_channel;

/*
 * struct scmi_msg_channel - Shared memory buffer for a agent-to-server channel
 *
 * @shm_addr: Address of the shared memory for the SCMI channel
 * @shm_size: Byte size of the shared memory for the SCMI channel
 * @busy: True when channel is busy, flase when channel is free
 * @threaded: True is executed in a threaded context, false otherwise
 */
struct scmi_msg_channel {
	struct io_pa_va shm_addr;
	size_t shm_size;
	bool busy;
	bool threaded;
};

#ifdef CFG_SCMI_MSG_SMT
/*
 * Initialize SMT memory buffer, called by platform at init for each
 * agent channel using the SMT header format.
 * This function depends on CFG_SCMI_MSG_SMT.
 *
 * @channel: Pointer to the channel shared memory to be initialized
 */
void scmi_smt_init_agent_channel(struct scmi_msg_channel *channel);

/*
 * Set SMT shared buffer location
 *
 * @channel: SCMI channel reference
 * @base: virtual address of the shared buffer or NULL to clear the reference
 */
void scmi_smt_set_shared_buffer(struct scmi_msg_channel *channel, void *base);
#else
static inline
void scmi_smt_init_agent_channel(struct scmi_msg_channel *channel __unused)
{
	panic();
}

static inline
void scmi_smt_set_shared_buffer(struct scmi_msg_channel *channel __unused,
				void *base __unused)
{
}
#endif /* CFG_SCMI_MSG_SMT */

#ifdef CFG_SCMI_MSG_SMT_FASTCALL_ENTRY
/*
 * Process SMT formatted message in a fastcall SMC execution context.
 * Called by platform on SMC entry. When returning, output message is
 * available in shared memory for agent to read the response.
 * This function depends on CFG_SCMI_MSG_SMT_FASTCALL_ENTRY.
 *
 * @channel_id: SCMI channel ID the SMT belongs to
 */
void scmi_smt_fastcall_smc_entry(unsigned int channel_id);
#else
static inline void scmi_smt_fastcall_smc_entry(unsigned int channel_id __unused)
{
}
#endif

#ifdef CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY
/*
 * Process SMT formatted message in a secure interrupt execution context.
 * Called by platform interrupt handler. When returning, output message is
 * available in shared memory for agent to read the response.
 * This function depends on CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY.
 *
 * @channel_id: SCMI channel ID the SMT belongs to
 */
void scmi_smt_interrupt_entry(unsigned int channel_id);
#else
static inline void scmi_smt_interrupt_entry(unsigned int channel_id __unused)
{
}
#endif

#ifdef CFG_SCMI_MSG_SMT_THREAD_ENTRY
/*
 * Process SMT formatted message in a TEE thread execution context.
 * When returning, output message is available in shared memory for
 * agent to read the response.
 * This function depends on CFG_SCMI_MSG_SMT_THREAD_ENTRY.
 *
 * @channel_id: SCMI channel ID the SMT belongs to
 */
void scmi_smt_threaded_entry(unsigned int channel_id);
#else
static inline void scmi_smt_threaded_entry(unsigned int channel_id __unused)
{
}
#endif

#ifdef CFG_SCMI_MSG_SHM_MSG
/*
 * Process MSG formatted message in a TEE thread execution context.
 * When returning, output message is available in shared memory for
 * agent to read the response.
 * This function depends on CFG_SCMI_MSG_MSG_THREAD_ENTRY.
 *
 * @channel_id: SCMI channel ID
 * @in_buf: Shared buffer storing input SCMI message
 * @in_size: Byte size of @in_buf, including MSG header and message payload
 * @out_buf: Shared buffer storing input SCMI message
 * @out_size: [in] @out_buf max byte size
 *            [out] @out_buf output byte size (MSG header and message payload)
 */
TEE_Result scmi_msg_threaded_entry(unsigned int channel_id,
				   void *in_buf, size_t in_size,
				   void *out_buf, size_t *out_size);
#else
static inline TEE_Result scmi_msg_threaded_entry(unsigned int chan_id __unused,
						 void *in_buf __unused,
						 size_t in_size __unused,
						 void *out_buf __unused,
						 size_t *out_size __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/* Platform callback functions */

/*
 * Return the SCMI channel related to an agent
 * @channel_id: SCMI channel ID
 * Return a pointer to channel on success, NULL otherwise
 */
struct scmi_msg_channel *plat_scmi_get_channel(unsigned int channel_id);

/* Scmi-msg uses the channel ID as handle. Must channel_id is valid */
static inline unsigned int scmi_smt_channel_handle(unsigned int channel_id)
{
	assert(plat_scmi_get_channel(channel_id));

	return channel_id;
}

/*
 * Return how many SCMI protocols supported by the platform
 * According to the SCMI specification, this function does not target
 * a specific channel ID and shall return all platform known capabilities.
 */
size_t plat_scmi_protocol_count(void);

/*
 * Get the count and list of SCMI protocols (but base) supported for an agent
 *
 * @channel_id: SCMI channel ID
 * Return a pointer to a null terminated array supported protocol IDs.
 */
const uint8_t *plat_scmi_protocol_list(unsigned int channel_id);

/* Get the name of the SCMI vendor for the platform */
const char *plat_scmi_vendor_name(void);

/* Get the name of the SCMI sub-vendor for the platform */
const char *plat_scmi_sub_vendor_name(void);

/* Handlers for SCMI Clock protocol services */

/*
 * Return number of clock controllers for an agent
 * @channel_id: SCMI channel ID
 * Return number of clock controllers
 */
size_t plat_scmi_clock_count(unsigned int channel_id);

/*
 * Get clock controller string ID (aka name)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * Return pointer to name or NULL
 */
const char *plat_scmi_clock_get_name(unsigned int channel_id,
				     unsigned int scmi_id);

/*
 * Get clock possible rate as an array of frequencies in Hertz.
 *
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * @start_index: Requested start index for the exposed rates array
 * @rates: Output rates array or NULL if only querying @nb_elts
 * @nb_elts: [in] Array size of @rates, [out] Number of rates loaded in @rates
 * Return an SCMI compliant error code
 */
int32_t plat_scmi_clock_rates_array(unsigned int channel_id,
				    unsigned int scmi_id, size_t start_index,
				    unsigned long *rates, size_t *nb_elts);

/*
 * Get clock possible rate as range with regular steps in Hertz
 *
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * @min_max_step: 3 cell array for min, max and step rate data
 * Return an SCMI compliant error code
 */
int32_t plat_scmi_clock_rates_by_step(unsigned int channel_id,
				      unsigned int scmi_id,
				      unsigned long *min_max_step);

/*
 * Get clock rate in Hertz
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * Return clock rate or 0 if not supported
 */
unsigned long plat_scmi_clock_get_rate(unsigned int channel_id,
				       unsigned int scmi_id);

/*
 * Set clock rate in Hertz
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * @rate: Target clock frequency in Hertz
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_clock_set_rate(unsigned int channel_id, unsigned int scmi_id,
				 unsigned long rate);

/*
 * Get clock state (enabled or disabled)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * Return 1 if clock is enabled, 0 if disables, or a negative SCMI error code
 */
int32_t plat_scmi_clock_get_state(unsigned int channel_id,
				  unsigned int scmi_id);

/*
 * Get clock state (enabled or disabled)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * @enable_not_disable: Enable clock if true, disable clock otherwise
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_clock_set_state(unsigned int channel_id, unsigned int scmi_id,
				  bool enable_not_disable);

/* Handlers for SCMI Reset Domain protocol services */

/*
 * Return number of reset domains for the agent
 * @channel_id: SCMI channel ID
 * Return number of reset domains
 */
size_t plat_scmi_rd_count(unsigned int channel_id);

/*
 * Get reset domain string ID (aka name)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI reset domain ID
 * Return pointer to name or NULL
 */
const char *plat_scmi_rd_get_name(unsigned int channel_id,
				  unsigned int scmi_id);

/*
 * Perform a reset cycle on a target reset domain
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI reset domain ID
 * @state: Target reset state (see SCMI specification, 0 means context loss)
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_rd_autonomous(unsigned int channel_id, unsigned int scmi_id,
				unsigned int state);

/*
 * Assert or deassert target reset domain
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI reset domain ID
 * @assert_not_deassert: Assert domain if true, otherwise deassert domain
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_rd_set_state(unsigned int channel_id, unsigned int scmi_id,
			       bool assert_not_deassert);

/* Handlers for SCMI Voltage Domain protocol services */

/*
 * Return number of voltage domain for an agent
 * @channel_id: SCMI channel ID
 * Return number of voltage domains
 */
size_t plat_scmi_voltd_count(unsigned int channel_id);

/*
 * Get clock controller string ID (aka name)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * Return pointer to name or NULL
 */
const char *plat_scmi_voltd_get_name(unsigned int channel_id,
				     unsigned int scmi_id);

/*
 * Get voltage domain possible levels as an array of voltages in microvolt.
 *
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * @start_index: Level index to start from.
 * @levels: If NULL, function returns, else output rates array
 * @nb_elts: Array size of @levels.
 * Return an SCMI compliant error code
 */
int32_t plat_scmi_voltd_levels_array(unsigned int channel_id,
				     unsigned int scmi_id, size_t start_index,
				     long *levels, size_t *nb_elts);

/*
 * Get voltage domain possible levels as range with regular steps in microvolt
 *
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * @min_max_step: 3 cell array for min, max and step voltage data
 * Return an SCMI compliant error code
 */
int32_t plat_scmi_voltd_levels_by_step(unsigned int channel_id,
				       unsigned int scmi_id,
				       long *min_max_step);

/*
 * Get current voltage domain level in microvolt
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * @level: Out parameter for the current voltage level
 * Return an SCMI compliant error code
 */
int32_t plat_scmi_voltd_get_level(unsigned int channel_id, unsigned int scmi_id,
				  long *level);

/*
 * Set voltage domain level voltage domain
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI clock ID
 * @level: Target voltage domain level in microvolt
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_voltd_set_level(unsigned int channel_id, unsigned int scmi_id,
				  long level);

/*
 * Get voltage domain state configuration (enabled or disabled)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * @config: output state configuration value SCMI_VOLTAGE_DOMAIN_CONFIG_*
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_voltd_get_config(unsigned int channel_id,
				   unsigned int scmi_id, uint32_t *config);

/*
 * Get voltage domain state configuration (enabled or disabled)
 * @channel_id: SCMI channel ID
 * @scmi_id: SCMI voltage domain ID
 * @config: Target state configuration value SCMI_VOLTAGE_DOMAIN_CONFIG_*
 * Return a compliant SCMI error code
 */
int32_t plat_scmi_voltd_set_config(unsigned int channel_id,
				   unsigned int scmi_id, uint32_t config);

#endif /* SCMI_MSG_H */
