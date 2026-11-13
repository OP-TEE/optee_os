/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_PRIVATE_H
#define QCOM_MBOX_PRIVATE_H

/*
 * Driver-internal header for the Qualcomm mailbox framework.
 *
 * Included by the framework core (qcom_mbox.c), the transport backend
 * (qcom_mbox_qmp_lite.c) and the per-SoC channel table
 * (<soc>/qcom_mbox_plat.c).  Consumers include <drivers/qcom/mbox/qcom_mbox.h>
 * only and see struct qcom_mbox_chan as an opaque handle.
 *
 * The SoC code implements plat_qcom_mbox_get_data() to return a
 * statically-allocated struct qcom_mbox_plat_data describing all available
 * channels (see bobcat/qcom_mbox_plat.c for an example).
 *
 * Constraints
 * -----------
 * - configs[N] permanently maps to slots[N].
 * - num_channels must equal ARRAY_SIZE(configs) == ARRAY_SIZE(slots).
 * - All arrays must be statically allocated and remain valid for the
 *   lifetime of the driver; the framework does not copy or cache them.
 * - plat_qcom_mbox_get_data() must return a non-NULL pointer.
 *
 * IRQ fields
 * ----------
 * struct qcom_mbox_chan embeds the IRQ state managed by the framework core.
 * struct qcom_mbox_chan_config carries the optional interrupt descriptor
 * supplied by the SoC code.  When itr_chip is NULL the channel operates in
 * polling-only mode and qcom_mbox_enable_irq() returns
 * TEE_ERROR_NOT_SUPPORTED.
 *
 * struct itr_chip and struct itr_handler are only forward-declared so that
 * this header does not depend on <kernel/interrupt.h>.
 */

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct itr_chip;
struct itr_handler;

/*
 * struct qcom_mbox_ops — transport operations table.
 *
 * Every transport backend must populate all function pointers; NULL entries
 * are rejected by config_validate() in qcom_mbox.c.
 *
 * init:       one-time channel setup; called by qcom_mbox_request().
 *             Returns TEE_SUCCESS on success, TEE_ERROR_* on failure.
 *             On failure init() must leave the channel untouched; the
 *             transport cleans up after itself and deinit() is not called.
 * deinit:     tear down a channel whose init() succeeded; called by
 *             qcom_mbox_release().  Must not fail.
 * process:    advance the state machine; set event bits in *events.
 *             Called by qcom_mbox_process().  Returns TEE_SUCCESS on success.
 * send:       transmit a message; len <= chan->mtu.
 *             Called by qcom_mbox_send().  Returns TEE_SUCCESS on success.
 * recv:       receive a message; updates *len on success.
 *             Called by qcom_mbox_recv().  Returns TEE_SUCCESS on success.
 * rx_pending: return true if at least one message is waiting.
 *             Called by qcom_mbox_process() to refresh the RX_READY level
 *             event.
 */
struct qcom_mbox_ops {
	TEE_Result (*init)(struct qcom_mbox_chan *chan);
	void       (*deinit)(struct qcom_mbox_chan *chan);
	TEE_Result (*process)(struct qcom_mbox_chan *chan, uint32_t *events);
	TEE_Result (*send)(struct qcom_mbox_chan *chan, const void *buf,
			   size_t len);
	TEE_Result (*recv)(struct qcom_mbox_chan *chan, void *buf, size_t *len);
	bool       (*rx_pending)(struct qcom_mbox_chan *chan);
};

/*
 * struct qcom_mbox_signal_config - MMIO doorbell descriptor used by the
 * transport configuration.
 *
 * @reg:   virtual address of the interrupt-set register.
 *         Set to 0 to disable signaling (polling-only mode).
 * @value: value to write to @reg when signaling the remote.
 */
struct qcom_mbox_signal_config {
	vaddr_t		reg;
	uint32_t	value;
};

/*
 * struct qcom_mbox_chan_config - immutable per-channel configuration.
 *
 * Populated by the SoC code and passed to the framework via
 * struct qcom_mbox_plat_data.
 *
 * @name:           unique null-terminated channel identifier.
 * @ops:            transport operations table; all pointers must be non-NULL.
 * @transport_cfg:  opaque pointer to transport-specific configuration
 *                  (e.g. struct qcom_mbox_qmp_lite_config *).
 * @transport_priv: opaque pointer to transport-specific runtime state
 *                  (e.g. struct qcom_mbox_qmp_lite_priv *).
 * @itr_chip:       interrupt controller for the incoming notification IRQ.
 *                  NULL disables IRQ-assisted wakeup (polling-only mode).
 * @itr_num:        interrupt number within @itr_chip.  Ignored when
 *                  @itr_chip is NULL.
 */
struct qcom_mbox_chan_config {
	const char			*name;
	const struct qcom_mbox_ops	*ops;
	const void			*transport_cfg;
	void				*transport_priv;
	struct itr_chip			*itr_chip;
	size_t				 itr_num;
};

/*
 * struct qcom_mbox_chan - runtime channel handle.
 *
 * Embedded in struct qcom_mbox_chan_slot (one per channel slot) and returned
 * to callers by qcom_mbox_request() as an opaque handle.
 *
 * Framework-managed fields:
 * @cfg:            pointer to the static channel configuration.
 * @ready:          true after a successful init(); cleared on release.
 * @mtu:            effective TX capacity in bytes; 0 until transport reports.
 * @pending_events: accumulated edge/level events not yet returned to caller.
 * @sticky_events:  latched error events; cleared only on release.
 *
 * IRQ-assisted wakeup fields (protected by @irq_lock):
 * @notify_cb:      notification callback; NULL in polling-only mode.
 * @notify_priv:    opaque value forwarded to @notify_cb.
 * @itr_hdlr:       allocated interrupt handler; NULL when IRQ is disabled.
 * @irq_enabled:    true when the interrupt is currently enabled.
 * @irq_pending:    set by the IRQ handler; cleared by qcom_mbox_process().
 * @irq_lock:       spinlock protecting all IRQ fields above.
 */
struct qcom_mbox_chan {
	const struct qcom_mbox_chan_config	*cfg;
	bool					 ready;
	size_t					 mtu;
	uint32_t				 pending_events;
	uint32_t				 sticky_events;
	qcom_mbox_notify_cb_t			 notify_cb;
	void					*notify_priv;
	struct itr_handler			*itr_hdlr;
	bool					 irq_enabled;
	bool					 irq_pending;
	unsigned int				 irq_lock;
};

/*
 * struct qcom_mbox_chan_slot - per-channel runtime slot.
 *
 * Allocated statically by the SoC code (one per channel).  The framework
 * core owns all fields; backends must not access them directly.
 *
 * @chan:    embedded channel handle returned to callers.
 * @in_use:  true while the slot is claimed; protected by the framework's
 *           internal mbox_slot_lock spinlock.
 */
struct qcom_mbox_chan_slot {
	struct qcom_mbox_chan	chan;
	bool			in_use;
};

/*
 * struct qcom_mbox_plat_data - SoC-supplied channel table.
 *
 * @configs:      pointer to the immutable channel configuration array.
 * @slots:        pointer to the mutable runtime slot array.
 * @num_channels: number of entries in both arrays.
 */
struct qcom_mbox_plat_data {
	const struct qcom_mbox_chan_config	*configs;
	struct qcom_mbox_chan_slot		*slots;
	size_t					 num_channels;
};

/*
 * plat_qcom_mbox_get_data() - return the SoC channel table.
 *
 * Must be implemented by the SoC code.  Called by the framework core on
 * every qcom_mbox_request() to obtain the channel configuration and runtime
 * slot arrays.
 *
 * The returned pointer must be non-NULL and must remain valid for the
 * lifetime of the driver.  The backing data must be statically allocated.
 */
const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void);

/*
 * qcom_mbox_chan_is_ready() - test whether a channel handle is usable.
 *
 * Returns true only when chan is non-NULL and has been successfully
 * initialised via qcom_mbox_request().  Used internally by the framework
 * core to guard all channel operations.
 */
static inline bool qcom_mbox_chan_is_ready(const struct qcom_mbox_chan *chan)
{
	return chan && chan->ready;
}

#endif /* QCOM_MBOX_PRIVATE_H */
