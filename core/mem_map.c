/* Copyright 2013-2018 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Memory layout for skiboot
 */

#include <inttypes.h>
#include <skiboot.h>
#include <mem-map.h>
#include <libfdt_env.h>
#include <lock.h>
#include <device.h>
#include <cpu.h>
#include <chip.h>
#include <affinity.h>
#include <types.h>
#include <mem_region.h>

unsigned long top_of_ram = SKIBOOT_BASE + SKIBOOT_SIZE;

struct mem_region skiboot_os_reserve = {
	.name		= "ibm,os-reserve",
	.start		= 0,
	.len		= SKIBOOT_BASE,
	.type		= REGION_OS,
};

struct mem_region skiboot_heap = {
	.name		= "ibm,firmware-heap",
	.start		= HEAP_BASE,
	.len		= HEAP_SIZE,
	.type		= REGION_SKIBOOT_HEAP,
};

struct mem_region skiboot_code_and_text = {
	.name		= "ibm,firmware-code",
	.start		= SKIBOOT_BASE,
	.len		= HEAP_BASE - SKIBOOT_BASE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_after_heap = {
	.name		= "ibm,firmware-data",
	.start		= HEAP_BASE + HEAP_SIZE,
	.len		= SKIBOOT_BASE + SKIBOOT_SIZE - (HEAP_BASE + HEAP_SIZE),
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_cpu_stacks = {
	.name		= "ibm,firmware-stacks",
	.start		= CPU_STACKS_BASE,
	.len		= 0, /* TBA */
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_mambo_kernel = {
	.name		= "ibm,firmware-mambo-kernel",
	.start		= (unsigned long)KERNEL_LOAD_BASE,
	.len		= KERNEL_LOAD_SIZE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_mambo_initramfs = {
	.name		= "ibm,firmware-mambo-initramfs",
	.start		= (unsigned long)INITRAMFS_LOAD_BASE,
	.len		= INITRAMFS_LOAD_SIZE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

