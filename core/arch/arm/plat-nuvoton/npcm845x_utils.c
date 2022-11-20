/*
 *  Copyright (c) 2022 Nuvoton Technology Corp.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <kernel/linker.h>
#include <npcm845x_trace.h>
#include <npcm845x_utils.h>
#include <npcm845x_version.h>

void print_version(void)
{
	TMSG(COLOR_MAGENTA);
	TMSG(">================================================");
	TMSG("OP-TEE OS Version %s", core_v_str);
	TMSG("Nuvoton OP-TEE OS Version %d.%d.%d%s",
			NPCMX845_OPTEE_VERSION_MAJOR,
			NPCMX845_OPTEE_VERSION_MINOR,
			NPCMX845_OPTEE_VERSION_PATCH,
			NPCMX845_OPTEE_VERSION_BUILD);
	TMSG(">================================================");
	TMSG(COLOR_NORMAL);
}

