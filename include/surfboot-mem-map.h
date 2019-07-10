/* Copyright 2013-2019 IBM Corp.
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

#ifndef __MEM_MAP_H
#define __MEM_MAP_H

/* This is our main offset for relocation. All our buffers
 * are offset from that and our code relocates itself to
 * that location
 */
#define SURFBOOT_BASE		0x600000

#define STACK_SHIFT		14
#define STACK_SIZE		(1 << STACK_SHIFT)

/* End of the exception region we copy from 0x0. 0x0-0x100 will have
 * IPL data and is not actually for exception vectors.
 */
#define EXCEPTION_VECTORS_END	0x2000

/* We keep a gap of 1M for surfboot text & bss for now. We will
 * then we have our heap which goes up to base + 512k.
 * Hopefully that's enough...
 */
#define HEAP_BASE		(SURFBOOT_BASE + 0x00c0000)
#define HEAP_SIZE		0x0040000

/* This is the location of our console buffer, after the HEAP, it's 64k */
#define INMEM_CON_START		(HEAP_BASE+HEAP_SIZE)
#define INMEM_CON_LEN  		0x10000

/* Total size of the above area
 *
 * (Ensure this has at least a 64k alignment)
 */
#define SURFBOOT_SIZE		((INMEM_CON_START + INMEM_CON_LEN) - SURFBOOT_BASE)

/* We start laying out the CPU stacks from here, indexed by PIR
 * each stack is STACK_SIZE in size (naturally aligned power of
 * two) and the bottom of the stack contains the cpu thread
 * structure for the processor, so it can be obtained by a simple
 * bit mask from the stack pointer. Within the CPU stack is divided
 * into a normal and emergency stack to cope with a single level of
 * re-entrancy.
 *
 * The size of this array is dynamically determined at boot time
 */
#define CPU_STACKS_BASE		(SURFBOOT_BASE + SURFBOOT_SIZE)

/*
 * Address at which we load the kernel LID. This is also where
 * we expect a passed-in kernel if booting without FSP and
 * without a built-in kernel.
 */

#define KERNEL_LOAD_BASE	((void *)0x300000)
#define KERNEL_LOAD_SIZE	0x0300000

#define INITRAMFS_LOAD_BASE	KERNEL_LOAD_BASE + KERNEL_LOAD_SIZE
#define INITRAMFS_LOAD_SIZE	0x00000000

/* Size allocated to build the device-tree - 16k */
#define	DEVICE_TREE_MAX_SIZE	0x4000


#endif /* __MEM_MAP_H */
