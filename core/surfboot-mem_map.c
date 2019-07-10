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
#include <surfboot-mem-map.h>
#include <skiboot.h>
#include <libfdt_env.h>
#include <lock.h>
#include <device.h>
#include <cpu.h>
#include <chip.h>
#include <affinity.h>
#include <types.h>
#include <mem_region.h>

unsigned long top_of_ram = SURFBOOT_BASE + SURFBOOT_SIZE;
int device_tree_max_size = DEVICE_TREE_MAX_SIZE;
struct cpu_stack * const cpu_stacks = (struct cpu_stack *)CPU_STACKS_BASE;
void* kernel_load_base = KERNEL_LOAD_BASE;
const uint64_t kernel_load_size = KERNEL_LOAD_SIZE;
void* initramfs_load_base = INITRAMFS_LOAD_BASE;
const uint64_t initramfs_load_size = INITRAMFS_LOAD_SIZE;
uint64_t skiboot_base = SURFBOOT_BASE;

struct mem_region skiboot_os_reserve = {
	.name		= "ibm,os-reserve",
	.start		= 0,
	.len		= SURFBOOT_BASE,
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
	.start		= SURFBOOT_BASE,
	.len		= HEAP_BASE - SURFBOOT_BASE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_after_heap = {
	.name		= "ibm,firmware-data",
	.start		= HEAP_BASE + HEAP_SIZE,
	.len		= SURFBOOT_BASE + SURFBOOT_SIZE - (HEAP_BASE + HEAP_SIZE),
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
	.start		= (unsigned long)0,
	.len		= 0,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct mem_region skiboot_mambo_initramfs = {
	.name		= "ibm,firmware-mambo-initramfs",
	.start		= (unsigned long)0,
	.len		= 0,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

