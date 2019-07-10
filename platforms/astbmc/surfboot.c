/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * A tiny base platform for BMC based systems for Surfboot
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>

#include "astbmc.h"
#include "ast.h"

static bool surfboot_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,powernv"))
		return false;

	return true;
}

DECLARE_PLATFORM(surfboot) = {
	.name			= "Surfboot",
	.probe			= surfboot_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2500_openbmc,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
