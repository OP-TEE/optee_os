/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <compiler.h>
#include <tee_api_types.h>


void console_init(void);
void console_putc(int ch);
void console_flush(void);

struct serial_chip;
void register_serial_console(struct serial_chip *chip);

#ifdef CFG_DT
/*
 * Get console info from a reacheable DTB. Check the embedded DTB and fall
 * back to the external DTB.
 *
 * If the DTB does not specify a chosen (or secure-chosen) node, we assume
 * DTB does not provide specific console directive. Early console may remain.
 * If the DTB does not specify any console in the chosen (or secure-chosen)
 * node, we assume there is no console. Early console would be disabled.
 *
 * @fdt_out: Output DTB address where console directive is found
 * @offs_out: Output offset in the DTB where console directive is found
 * @path_out: Output string configuration of the console from the DTB.
 * (*path_out) shall be freed using nex_free().
 * @params_out: Output console parameters found from the DTB.
 * (*params_out) shall be freed using nex_free().
 *
 * Return a TEE_Result compliant return value
 *
 */
TEE_Result get_console_node_from_dt(void *fdt, int *offs_out,
				    char **path_out, char **params_out);

/*
 * Check if the /secure-chosen or /chosen node in the DT contains an
 * stdout-path value for which we have a compatible driver. If so, switch
 * the console to this device.
 */
void configure_console_from_dt(void);
#else
static inline void configure_console_from_dt(void)
{}
#endif /* !CFG_DT */

#endif /* CONSOLE_H */

