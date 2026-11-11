/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _Q6SS_H_
#define _Q6SS_H_

#include <stdbool.h>
#include <tee_api_types.h>
#include <types_ext.h>

#include "pas_subsys.h"

/*
 * DTB stage of every DSP: start passes the DTB, chip and platform in the
 * boot parameters; shutdown resets unless the subsystem was reset since
 */
extern const struct qcom_pas_ops q6ss_dtb_ops;

/* VA of the QDSP6SS block of the subsystem, 0 if unmapped */
vaddr_t q6ss_base(struct qcom_pas_data *data);

/* Image stage shutdown: reset the subsystem through its clock group */
TEE_Result q6ss_shutdown(struct qcom_pas_data *data);

/*
 * Run the boot FSM from the programmed EVB with the retention resets
 * disarmed; @start_core releases the core before the FSM runs.
 */
TEE_Result q6ss_boot(vaddr_t q6ss, bool start_core);

#endif /* _Q6SS_H_ */
