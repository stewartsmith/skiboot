/* Copyright 2018 IBM Corp.
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

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>
#include <cmpxchg.h>
#include <cpu.h>
#include <opal.h>
#include <skiboot.h>
#include <stack.h>
#include <timebase.h>
#include <trace.h>

static bool vm_setup = false;
static bool vm_globals_allocated = false;

#define SLB_SZ		(256UL*1024*1024)
#define SLB_NR		32
#define LOCAL_SLB_NR	2
#define GLOBAL_SLB_NR	(SLB_NR - LOCAL_SLB_NR)
#define LOCAL_SLB_BASE	GLOBAL_SLB_NR

#define LOCAL_EA_BEGIN	0x0800000000000000ULL
#define LOCAL_EA_END	0x0900000000000000ULL

static void __nomcount slb_install(unsigned long esid, unsigned long vsid, unsigned int index)
{
	unsigned long rs;
	unsigned long rb;

	rs = vsid << (63-51);		/* 256MB VSID */
	rs |= 1UL << (63-53);		/* Kp = 1 */

	rb = esid << (63-35);		/* 256MB ESID */
	rb |= 1UL << (63-36);		/* V = 1 */
	rb |= index;

	asm volatile("slbmte %0,%1" : : "r"(rs), "r"(rb) : "memory");
}

#if 0
static void slb_remove(unsigned long esid)
{
	asm volatile("isync ; slbie %0 ; isync" : : "r"(esid << 28) : "memory");
}
#endif

static void slb_remove_all(void)
{
	asm volatile("isync ; slbmte %0,%0 ; slbia ; isync" : : "r"(0) : "memory");
}

static void __nomcount slb_add(unsigned long ea)
{
	struct cpu_thread *cpu = this_cpu();
	uint64_t esid = ea >> 28;
	uint64_t vsid = ea >> 28;

	slb_install(esid, vsid, cpu->vm_slb_rr);

	cpu->vm_slb_rr++;
	if (cpu->vm_slb_rr == GLOBAL_SLB_NR)
		cpu->vm_slb_rr = 0;
}

struct hpte {
	uint64_t dword[2];
};

struct hpteg {
	struct hpte hpte[8];
};

static struct hpteg *htab;
static unsigned long htab_shift;
static unsigned long htab_pteg_mask;

static struct lock htab_lock;

static void __nomcount htab_install(unsigned long va, unsigned long pa, int rw, int ex, int ci, bool local)
{
	unsigned long hash;
	struct hpteg *hpteg;
	struct hpte *hpte;
	unsigned long ava = va >> 23;
	unsigned long arpn = pa >> 12;
	unsigned long dw0, dw1;
	unsigned long _dw0;
	unsigned long _ava;
	unsigned int hstart, hend;
	unsigned int i;

	dw0 = ava << (63-56); /* AVA = ava */
	dw0 |= 0x1; /* V = 1 */
	if (local)
		dw0 |= 0x8; /* SW[0] = 1 */

	dw1 = (arpn << (63-43 - 8)); /* ARPN||LP = arpn */
	if (!rw)
		dw1 |= (1UL << (63 - 0)) | (1UL << (63 - 63 + 1)); /* pp = 110 */
	if (!ex)
		dw1 |= (1UL << (63 - 61)); /* N = 1 */
	dw1 |= (1UL << (63 - 60 + 1)); /* WIMG = 0010 */
	if (ci)
		dw1 |= (1UL << (63 - 60)) | (1UL << (63 - 60 + 2)); /* WIMG = 0111 */
	dw1 |= (1UL << (63 - 55)) | (1UL << (63 - 56)); /* R=C=1 */

	hash = ((va >> 12) & 0xffff) ^ ((va >> 28) & 0x7fffffffffUL);
	hpteg = &htab[hash & htab_pteg_mask];

	lock(&htab_lock);

	hstart = 0;
	hend = 7;

	for (i = hstart; i <= hend; i++) {
		hpte = &hpteg->hpte[i];

		_dw0 = be64_to_cpu(hpte->dword[0]);
		if (_dw0 & 1) {
			_ava = _dw0 >> (63 - 56);
			if (_ava == ava) {
				/* Replace insertion */
				goto install;
			}

			continue;
		}

		assert(!_dw0);
		goto install;
	}

	i = mftb();
	i = (i ^ (i >> 4)) & 0x7;
	hpte = &hpteg->hpte[i];

install:
	hpte->dword[0] = 0;
	eieio();
	hpte->dword[1] = cpu_to_be64(dw1);
	eieio();
	hpte->dword[0] = cpu_to_be64(dw0);
	asm volatile("ptesync" ::: "memory");
	unlock(&htab_lock);
}

static void htab_remove(unsigned long va, int local)
{
	unsigned long hash;
	struct hpteg *hpteg;
	unsigned long ava = va >> 23;
	unsigned long dw0;
	unsigned int hstart, hend;
	unsigned int i;

	dw0 = ava << (63-56);
	dw0 |= 0x1;
	if (local)
		dw0 |= 0x8;

	hash = ((va >> 12) & 0xffff) ^ ((va >> 28) & 0x7fffffffffUL);
	hpteg = &htab[hash & htab_pteg_mask];

	if (!local)
		lock(&htab_lock);
again:
	hstart = 0;
	hend = 7;

	for (i = hstart; i <= hend; i++) {
		struct hpte *hpte = &hpteg->hpte[i];
		unsigned long _raw_dw0, _dw0;

		_raw_dw0 = hpte->dword[0];
		_dw0 = be64_to_cpu(_raw_dw0);

		if (!(_dw0 & 1)) {
			assert(!_raw_dw0);
			continue;
		}

		if (_dw0 != dw0) {
			assert(_dw0 >> 7 != ava);
			continue;
		}

		if (local) {
			if (__cmpxchg64(&hpte->dword[0], _raw_dw0, 0) != _raw_dw0)
				goto again;
		} else {
			hpte->dword[0] = 0;
		}

		break;
	}

	if (local) {
		asm volatile("ptesync" ::: "memory");
		asm volatile("tlbiel %0" : : "r"(va & ~0xfffULL));
		asm volatile("ptesync" ::: "memory");
	} else {
		unlock(&htab_lock);
		asm volatile("ptesync" ::: "memory");
		asm volatile("tlbie %0,%1" : : "r"(va & ~0xfffULL), "r"(0));
		asm volatile("eieio ; tlbsync ; ptesync" ::: "memory");
	}
}

/*
 * Try to fix problems in callers if !strict.
 */
static bool vm_strict = false;

static struct list_head vm_maps = LIST_HEAD_INIT(vm_maps);
static struct lock vm_maps_lock;
static unsigned long nr_vm_maps;

static void __vm_map(const char *name, unsigned long addr, unsigned long len, unsigned long pa, bool r, bool w, bool x, bool ci, bool local)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;
	struct vm_map *new;
	struct vm_map *vmm;

	if (local) {
		new = &c->vm_local_map;
		new->name = name;
		new->address = addr;
		new->length = len;
		new->pa = pa;
		new->readable = r;
		new->writeable = w;
		new->executable = x;
		new->ci = ci;

		return;
	}

	new = zalloc(sizeof(*new));
	assert(new);

	new->name = name;
	new->address = addr;
	new->length = len;
	new->pa = pa;
	new->readable = r;
	new->writeable = w;
	new->executable = x;
	new->ci = ci;

	/* Can not take a d-side fault while holding this lock */
	if (vm_setup)
		vm_exit();
	lock(&vm_maps_lock);

	list_for_each(&vm_maps, vmm, list) {
		if (addr >= vmm->address + vmm->length)
			continue;
		if (addr + len <= vmm->address) {
			list_add_before(&vm_maps, &new->list, &vmm->list);
			goto found;
		}

		if (!vm_strict) {
			printf("vm_map_global %s %lx-%lx collided with vmm:%s %llx-%llx\n", name, addr, addr + len, vmm->name, vmm->address, vmm->address + vmm->length);
			list_add_before(&vm_maps, &new->list, &vmm->list);
			goto found;
		}
		assert(0);
	}
	list_add_tail(&vm_maps, &new->list);
found:
	nr_vm_maps++;
	unlock(&vm_maps_lock);
	if (vm_setup)
		vm_enter();
}

static void __vm_unmap(unsigned long addr, unsigned long len, bool local)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;
	unsigned long end = addr + len;
	struct vm_map *vmm;

	if (local) {
		vmm = &c->vm_local_map;
		assert(addr == vmm->address);
		assert(len == vmm->length);
		memset(vmm, 0, sizeof(struct vm_map));

		if (vm_setup) {
			while (addr < end) {
				htab_remove(addr, local);
				addr += PAGE_SIZE;
			}
		}

		return;
	}

	/* Can not take a d-side fault while holding this lock */
	if (vm_setup)
		vm_exit();
	lock(&vm_maps_lock);
	list_for_each(&vm_maps, vmm, list) {
		if (addr != vmm->address)
			continue;
		if (len != vmm->length)
			continue;
		goto found;
	}
	vmm = NULL;
	unlock(&vm_maps_lock);
	if (!vm_strict) {
		printf("unmap didn't find anything\n");
		backtrace();
		goto out;
	}
	assert(0);

found:
	list_del(&vmm->list);

	if (vm_setup) {
		while (addr < end) {
			htab_remove(addr, local);
			addr += PAGE_SIZE;
		}
	}

	nr_vm_maps--;
	unlock(&vm_maps_lock);
out:
	if (vm_setup)
		vm_enter();

	if (vmm)
		free(vmm);
}


void vm_map_global(const char *name, unsigned long addr, unsigned long len, bool rw, bool ci)
{
	__vm_map(name, addr, len, addr, true, rw, false, ci, false);
}

static void vm_map_global_text(const char *name, unsigned long addr, unsigned long len)
{
	__vm_map(name, addr, len, addr, true, false, true, false, false);
}

void vm_unmap_global(unsigned long addr, unsigned long len)
{
	__vm_unmap(addr, len, false);
}


void *vm_map(unsigned long addr, unsigned long len, bool rw)
{
	struct cpu_thread *c = this_cpu();
	unsigned long newaddr = (LOCAL_EA_BEGIN + ((unsigned long)c->pir << 30));
	unsigned long end = addr + len;
	unsigned long offset = addr & (PAGE_SIZE - 1);

	/* Can't do nested mappings */
	assert(!c->vm_local_map_inuse);
	c->vm_local_map_inuse = true;

	if (!c->vm_setup)
		return (void *)addr;

	end = (end + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	addr &= ~(PAGE_SIZE - 1);
	len = end - addr;

	assert(len < (1 << 28)); /* same segment */

	__vm_map("local", newaddr, len, addr, true, rw, false, false, true);

	return (void *)newaddr + offset;
}

void vm_unmap(unsigned long addr, unsigned long len)
{
	struct cpu_thread *c = this_cpu();
	unsigned long newaddr = (LOCAL_EA_BEGIN + ((unsigned long)c->pir << 30));
	unsigned long end = addr + len;

	assert(c->vm_local_map_inuse);
	c->vm_local_map_inuse = false;

	if (!c->vm_setup)
		return;

	end = (end + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	addr &= ~(PAGE_SIZE - 1);
	len = end - addr;

	assert(len < (1 << 28)); /* same segment */

	__vm_unmap(newaddr, len, true);
}

struct prte {
	unsigned long dword[2];
};

static struct prte *prtab;

static void vm_init_cpu(void)
{
	struct cpu_thread *c = this_cpu();
	unsigned long esid = (LOCAL_EA_BEGIN + ((unsigned long)c->pir << 30)) >> 28;
	unsigned long vsid = (LOCAL_EA_BEGIN + ((unsigned long)c->pir << 30)) >> 28;

	mtspr(SPR_LPCR, mfspr(SPR_LPCR) &
		~(PPC_BITMASK(0,3) | PPC_BIT(41) | PPC_BIT(43) | PPC_BIT(54)));
	mtspr(SPR_LPID, 0);
	mtspr(SPR_PID, 0);
	mtspr(SPR_HRMOR, 0);
	mtspr(SPR_PTCR, (unsigned long)prtab);
	mtspr(SPR_AMR, 0);
	mtspr(SPR_IAMR, 0);
	mtspr(SPR_AMOR, 0);
	mtspr(SPR_UAMOR, 0);

	slb_remove_all();
	slb_install(esid, vsid, LOCAL_SLB_BASE);
}

void vm_init_secondary(void)
{
	vm_init_cpu();
	vm_enter();
}

bool vm_realmode(void)
{
	struct cpu_thread *c = this_cpu();

	return !vm_setup || !c->vm_setup;
}

void vm_enter(void)
{
	struct cpu_thread *c = this_cpu();

	assert(vm_setup);
	if (c->vm_setup) {
		mtmsr(mfmsr() | (MSR_IR|MSR_DR));
		printf("CPU:%d vm_enter already entered\n", c->pir);
		backtrace();
		return;
	}
	c->vm_setup = true;
	mtmsr(mfmsr() | (MSR_IR|MSR_DR));
}

void vm_exit(void)
{
	struct cpu_thread *c = this_cpu();

	assert(vm_setup);
	if (!c->vm_setup) {
		mtmsr(mfmsr() & ~(MSR_IR|MSR_DR));
		printf("CPU:%d vm_exit already exited\n", c->pir);
		backtrace();
		return;
	}
	c->vm_setup = false;
	mtmsr(mfmsr() & ~(MSR_IR|MSR_DR));
}

bool __nomcount vm_dslb(uint64_t nia, uint64_t dar)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;

	assert(vm_setup);
	c->vm_setup = false;

	/*
	 * Per-cpu map ranges are bolted to per-cpu SLBs.
	 */
	assert((dar < LOCAL_EA_BEGIN) ||
		(dar >= LOCAL_EA_END));

	(void)nia;
	slb_add(dar);

	c->vm_setup = true;

	return true;
}

bool __nomcount vm_islb(uint64_t nia)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;

	assert(vm_setup);
	c->vm_setup = false;

	slb_add(nia);

	c->vm_setup = true;

	return true;
}

bool __nomcount vm_dsi(uint64_t nia, uint64_t dar, bool store)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;
	struct vm_map *vmm;
	uint64_t pa;
	bool ret = true;
	bool local;

	(void)nia;

	assert(vm_setup);
	c->vm_setup = false;

	if ((dar >= LOCAL_EA_BEGIN) && (dar < LOCAL_EA_END)) {
		local = true;
		vmm = &c->vm_local_map;
		if (dar >= vmm->address && dar < vmm->address + vmm->length)
			goto found;
		goto not_found;
	}

	local = false;

	lock(&vm_maps_lock);
	list_for_each(&vm_maps, vmm, list) {
		assert(vmm->pa == vmm->address);
		if (dar >= vmm->address && dar < vmm->address + vmm->length)
			goto found;
	}
	if (!vm_strict) {
		if (dar >= 0x0006000000000000 && dar < 0x0007000000000000)
			/* MMIO */
			htab_install(dar, dar, 1, 0, 1, false);
		else if (dar < LOCAL_EA_BEGIN)
			htab_install(dar, dar, 1, 0, 0, false);
		else
			ret = false;
		unlock(&vm_maps_lock);
		printf("Page fault with no VMM at NIA:0x%016llx DAR:0x%016llx, store:%d\n", nia, dar, store);
		backtrace();
		goto out;
	}
	unlock(&vm_maps_lock);
not_found:
	printf("  vmm not found\n");
	ret = false;
	assert(0);
	goto out;

found:
	pa = vmm->pa + (dar & ~(PAGE_SIZE - 1)) - vmm->address;
	if (!vmm->readable) {
		unlock(&vm_maps_lock);
		printf("  vmm not readable\n");
		ret = false;
		assert(0);
		goto out;
	}
	if (store && !vmm->writeable) {
		if (!vm_strict) {
			htab_install(dar, pa, store, 0, vmm->ci, local);
			unlock(&vm_maps_lock);
			printf("Page fault store to RO VMM:%s at NIA:0x%016llx DAR:0x%016llx\n", vmm->name, nia, dar);
			backtrace();
			goto out;
		}
		unlock(&vm_maps_lock);
		printf("  vmm not writeable\n");
		ret = false;
		assert(0);
		goto out;
	}

	htab_install(dar, pa, vmm->writeable, vmm->executable, vmm->ci, local);
	if (!local)
		unlock(&vm_maps_lock);

out:
	c->vm_setup = true;
	return ret;
}

bool __nomcount vm_isi(uint64_t nia)
{
	struct cpu_thread *c = this_cpu();
	bool vm_setup = c->vm_setup;

	assert(vm_setup);

	if (nia < (unsigned long)_stext)
		return false;
	if (nia >= (unsigned long)_etext)
		return false;

	c->vm_setup = false;
	htab_install(nia, nia, 0, 1, 0, false);
	c->vm_setup = true;

	return true;
}

static void cpu_stop_vm(void *arg __unused)
{
	vm_exit();
}

static void cpu_cleanup_vm(void *arg __unused)
{
	slb_remove_all();
	mtspr(SPR_PTCR, 0);
}

static void cpu_all_destroy_vm(void)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;

	jobs = zalloc(sizeof(struct cpu_job *) * cpu_max_pir + 1);
	assert(jobs);

	/* Stop all CPUs */
	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		jobs[cpu->pir] = cpu_queue_job(cpu, "cpu_stop_vm",
						cpu_stop_vm, NULL);
	}

	/* this cpu */
	cpu_stop_vm(NULL);

	/* Cleaup after all stop */
	for_each_available_cpu(cpu) {
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);
	}

	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		jobs[cpu->pir] = cpu_queue_job(cpu, "cpu_cleanup_vm",
						cpu_cleanup_vm, NULL);
	}

	/* this cpu */
	cpu_cleanup_vm(NULL);

	for_each_available_cpu(cpu) {
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);
	}

	free(jobs);
}

void vm_init(void)
{
	unsigned long stack_start = SKIBOOT_BASE + SKIBOOT_SIZE;
	unsigned long stack_end = stack_start + (cpu_max_pir + 1)*STACK_SIZE;
	unsigned long htab_nr_bytes;
	unsigned long htab_nr_ptegs;

	prtab = memalign(64*1024, 64*1024);
	assert(prtab);
	memset(prtab, 0, 64*1024);

	htab_shift = 18;
	htab_nr_bytes = 1UL << htab_shift;
	htab_nr_ptegs = htab_nr_bytes / sizeof(struct hpteg);
	htab_pteg_mask = htab_nr_ptegs - 1;
	htab = memalign(1UL << htab_shift, htab_nr_bytes);
	assert(htab);
	memset(htab, 0, htab_nr_bytes);

	prtab[0].dword[0] = cpu_to_be64((unsigned long)htab | (htab_shift - 18));
	prtab[0].dword[1] = 0;

	eieio();

	vm_init_cpu();

	cleanup_global_tlb();

	if (vm_globals_allocated)
		goto done;

	vm_map_global_text("OPAL text", (unsigned long)_stext,
		(unsigned long)_etext - (unsigned long)_stext);
	vm_map_global("OPAL rodata", (unsigned long)__rodata_start,
		(unsigned long)__rodata_end - (unsigned long)__rodata_start,
		false, false);
	vm_map_global("OPAL data", (unsigned long)_sdata,
		(unsigned long)_edata - (unsigned long)_sdata,
		true, false);
	vm_map_global("OPAL bss", (unsigned long)_sbss,
		(unsigned long)_ebss - (unsigned long)_sbss,
		true, false);
	vm_map_global("OPAL sym map", (unsigned long)__sym_map_start,
		(unsigned long)__sym_map_end - (unsigned long)__sym_map_start,
		false, false);
	vm_map_global("OPAL heap", HEAP_BASE, HEAP_SIZE, true, false);
	vm_map_global("Memory console", INMEM_CON_START, INMEM_CON_LEN, true, false);
	vm_map_global("Hostboot console", HBRT_CON_START, HBRT_CON_LEN, false, false);
	vm_map_global("SPIRA heap", SPIRA_HEAP_BASE, SPIRA_HEAP_SIZE, false, false);
	vm_map_global("PSI TCE table", PSI_TCE_TABLE_BASE, PSI_TCE_TABLE_SIZE_P8, false, false);
	vm_map_global("OPAL boot stacks", stack_start, stack_end - stack_start, true, false);
	vm_globals_allocated = true;

done:
	if (1) {
		struct vm_map *vmm;
		printf("VMM: SETUP\n");
		printf(" PRTAB:%p\n", prtab);
		printf(" HTAB: %p\n", htab);
		printf(" Global mappings\n");
		list_for_each(&vm_maps, vmm, list)
			printf("%28s 0x%08llx-0x%08llx\n", vmm->name,
				vmm->address, vmm->address + vmm->length);
	}

	vm_setup = true;

	vm_enter();
}

void vm_init_stacks(void)
{
	unsigned long stack_start = SKIBOOT_BASE + SKIBOOT_SIZE;
	unsigned long stack_end = stack_start + (cpu_max_pir + 1)*STACK_SIZE;
	struct cpu_thread *c = this_cpu();
	struct vm_map *vmm;

	/* Can not take a d-side fault while holdig this lock */
	if (c->vm_setup)
		mtmsr(mfmsr() & ~MSR_DR);
	lock(&vm_maps_lock);
	list_for_each(&vm_maps, vmm, list) {
		if (vmm->address >= stack_end)
			continue;
		if (vmm->address + vmm->length <= stack_start)
			continue;
		goto found;
	}
	unlock(&vm_maps_lock);
	assert(0);

found:
	vmm->name = "OPAL stacks";
	vmm->address = stack_start;
	vmm->length = stack_end - stack_start;
	unlock(&vm_maps_lock);
	if (c->vm_setup)
		mtmsr(mfmsr() | MSR_DR);
}

void vm_destroy(void)
{
	assert(vm_setup);

	if (1) {
		struct vm_map *vmm;
		printf("VMM: TEARDOWN\n");
		printf(" Global mappings\n");
		list_for_each(&vm_maps, vmm, list)
			printf("%28s 0x%08llx-0x%08llx\n", vmm->name,
				vmm->address, vmm->address + vmm->length);
	}

	cpu_all_destroy_vm();

	vm_setup = false;

	if (0) { /* XXX: leave for VMM enabled fast-reboot */
		while (!list_empty(&vm_maps)) {
			struct vm_map *vmm;
			vmm = list_pop(&vm_maps, struct vm_map, list);
			free(vmm);
		}
	}

	free(htab);
	htab = NULL;
	free(prtab);
	prtab = NULL;
}
