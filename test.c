#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h> /* for mmap(), munmap() */

#include <errno.h>
#include <string.h>

#include <math.h>

#define PAGE_SIZE				4096
#define PTRS_PER_PTE            512
#define PTRS_PER_PMD            512
#define PTRS_PER_PGD            512
#define PGDIR_SHIFT             30
#define PMD_SHIFT               21
#define PAGE_SHIFT				12

/*
 * Software defined PTE bits definition.
 */
#define PTE_VALID_MASK			(1 << 0)
#define PTE_YOUNG_MASK			(1 << 3)
#define PTE_FILE_MASK			(1 << 2)
#define PTE_DIRTY_MASK			(1 << 55)
#define PTE_RDONLY_MASK			(1 << 7)
#define PTE_UXN_MASK			(1 << 54)
#define PTE_VALID				0
#define PTE_YOUNG				10
#define PTE_FILE				2
#define PTE_DIRTY				55
#define PTE_RDONLY				7
#define PTE_UXN					54
#define pte_young(pte)          ((pte) & PTE_YOUNG)
#define pte_file(pte)           ((pte) & PTE_FILE)
#define pte_dirty(pte)          ((pte) & PTE_DIRTY)
#define pte_rdonly(pte)         ((pte) & PTE_RDONLY)
#define pte_uxn(pte)            ((pte) & PTE_UXN)

#define PAGESIZE2               (1 << PAGE_SHIFT)
#define PAGE_MASK2               (~(PAGESIZE2-1))

#define PHYS_MASK_SHIFT         40
#define PHYS_MASK               ((1 << PHYS_MASK_SHIFT) - 1)

#define pgd_index(addr)         (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr)         (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define __pte_index(addr)       (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

unsigned long get_bit(unsigned long n, int shift)
{
	return n & (1 << shift);
}

void dump_page_entry(unsigned long entry, unsigned long va)
{
	if (entry != 0) {
		unsigned int phys;
		unsigned long young;
		unsigned long file;
		unsigned long dirty;
		unsigned long read_only;
		unsigned long uxn;

		phys = (unsigned int) (entry & PHYS_MASK & PAGE_MASK2);
		young = (get_bit(entry, PTE_YOUNG) != 0);
		file = (get_bit(entry, PTE_FILE) != 0);
		dirty = (get_bit(entry, PTE_DIRTY) != 0);
		read_only = (get_bit(entry, PTE_RDONLY) != 0);
		uxn = (get_bit(entry, PTE_UXN) != 0);

		printf("0x%lx 0x%x %lu %lu %lu %lu %lu\n",
			va, phys, young, file, dirty, read_only, uxn);

	}
}

void dump_page_entry_verbose(unsigned long entry, unsigned long va)
{
	if (entry != 0) {
		unsigned int phys;
		unsigned long young;
		unsigned long file;
		unsigned long dirty;
		unsigned long read_only;
		unsigned long uxn;

		phys = (unsigned int) (entry & PHYS_MASK & PAGE_MASK2);
		young = (get_bit(entry, PTE_YOUNG) != 0);
		file = (get_bit(entry, PTE_FILE) != 0);
		dirty = (get_bit(entry, PTE_DIRTY) != 0);
		read_only = (get_bit(entry, PTE_RDONLY) != 0);
		uxn = (get_bit(entry, PTE_UXN) != 0);

		printf("0x%lx 0x%x %lu %lu %lu %lu %lu\n",
			va, phys, young, file, dirty, read_only, uxn);

	} else {

		printf("0x%lx 0x%x %lu %lu %lu %lu %lu\n",
			va, 0, 0L, 0L, 0L, 0L, 0L);
	}


}

int print_pte(void *pte, int pte_size)
{

	int i;
	unsigned long *pte_u = ((unsigned long *) ((void *) pte));

	for (i = 0; i < pte_size; i++) {

		if ((*pte_u) != 0L) {
			printf("%d:%lu %lu\n", i,
				(unsigned long) pte_u, *pte_u);
		}
		pte_u++;
	}

	return 0;

}


int inspect_curr_va(unsigned long curr_va,
	void *pgd_base,
	void (*foo)(unsigned long, unsigned long))
{
	int pgd_idx;
	unsigned long *pmd_base;
	int pmd_idx;
	unsigned long *pte_base;
	int pte_idx;
	unsigned long pte_entry;
	unsigned long *pgd_base2;

	pgd_base2 = (unsigned long *) pgd_base;
	pgd_idx = pgd_index(curr_va);

	if (!(pgd_base))
		return 0;


	pmd_base = (unsigned long *)(*(pgd_base2 + pgd_idx));
	pmd_idx = pmd_index(curr_va);

	if (!(pmd_base))
		return 0;


	pte_base = (unsigned long *)(*(pmd_base + pmd_idx));
	pte_idx = __pte_index(curr_va);

	if (!(pte_base))
		return 0;

	pte_entry = *(pte_base + pte_idx);

	(*foo)(pte_entry, curr_va);
	return 0;
}

int inspect(unsigned long begin_vaddr,
	unsigned long end_vaddr, void *pgd_base,
	void (*foo)(unsigned long, unsigned long))
{
	unsigned long curr_va;
	int ret_val;

	for (curr_va = begin_vaddr;
		curr_va < end_vaddr;
		curr_va += PAGE_SIZE) {
		ret_val = inspect_curr_va(curr_va, pgd_base, foo);
		if (ret_val)
			return ret_val;
	}

	return 0;
}

void error(int err)
{
	printf("ERROR: %s\n", strerror(err));
	exit(1);
}

int main(int argc, char *argv[])
{
	char *va_begin;
	char *va_end;
	char *pid;
	int verb; /* verbose option */

	pid_t target_pid;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;

	struct pagetable_layout_info pgtbl_info;
	void *pgd_base;
	void *pmd_base;
	void *pte_base;
	unsigned long pgd_size;
	unsigned long pmd_size;
	unsigned long pte_size;

	int ret_val;

	/* Getting/Parsing args */
	/* Expecting: ./vm_inspector [-v] pid va_begin va_end */
	if (argc == 5) {
		if (!strcmp(argv[1], "-v")) {
			verb = 1;
			pid = argv[2];
			va_begin = argv[3];
			va_end = argv[4];
		} else {
			printf("./vm_inspector [-v] pid va_begin va_end\n");
			return 1;
		}
	} else if (argc == 4) {
		verb = 0;
		pid = argv[1];
		va_begin = argv[2];
		va_end = argv[3];
	} else {
		printf("./vm_inspector [-v] pid va_begin va_end\n");
		return 1;
	}

	/* Turn args into proper types */
	target_pid = (pid_t) strtol(pid, NULL, 10);
	begin_vaddr = strtoul(va_begin, NULL, 16);
	end_vaddr = strtoul(va_end, NULL, 16);

	printf("pid: %d\nva_begin: %lu\nva_end: %lu\n",
		(int) target_pid, begin_vaddr, end_vaddr);

	if (end_vaddr < begin_vaddr) {
		printf("va_end needs to be larger than va_begin\n");
		return 1;
	}

	if (begin_vaddr % PAGE_SIZE != 0) {
		printf("Aligning va_begin with PAGE_SIZE (rounding down)\n");
		begin_vaddr = begin_vaddr - (begin_vaddr % PAGE_SIZE);
	}

	if (end_vaddr % PAGE_SIZE != 0) {
		printf("Aligning va_end with PAGE_SIZE (rounding up)\n");
		end_vaddr = end_vaddr + (PAGE_SIZE - (end_vaddr % PAGE_SIZE));
	}

	/* get_pagetable_layout syscall */
	if (syscall(244, &pgtbl_info, sizeof(struct pagetable_layout_info)))
		error(errno);

	/*printf("pgdir_shift: %u\npmd_shift: %u\npage_shift: %u\n",
			pgtbl_info.pgdir_shift,
			pgtbl_info.pmd_shift,
			pgtbl_info.page_shift);*/

	/* area sizes in number of entries -could have used above offsets */
	pgd_size = PTRS_PER_PGD; /* 512 */
	pmd_size = PTRS_PER_PMD*pgd_size; /* 512*512 */

	/* calculating pte_size based on
	given addresses + 2 tables padding: B */
	/* actual size PTRS_PER_PTE*pmd_size or 512*512*512 */

	pte_size = ((end_vaddr - begin_vaddr) / PAGE_SIZE) + 2 *
		PTRS_PER_PTE;
	/*printf("PTE_SIZE: %lu\n", pte_size);*/
	/* make pte_size at least 2 tables long */

	/* MAPPING */
	pgd_base = mmap(NULL, (size_t) (sizeof(void *))*pgd_size,
		PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
			-1, 0);
	if (pgd_base == NULL) {
		printf("ERROR: mmap returns NULL pgd pointer\n");
		return 1;
	}
	if (pgd_base == (void *) -1) {
		printf("pgd could not map to mem\n");
		error(errno);
	}

	pmd_base = mmap(NULL, (size_t) (sizeof(void *))*pmd_size,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1, 0);
	if (pmd_base == NULL) {
		printf("ERROR: mmap returns NULL pmd pointer\n");
		return 1;
	}
	if (pmd_base == (void *) -1) {
		printf("pmd could not map to mem\n");
		if (munmap(pgd_base, (size_t) (sizeof(void *))*pgd_size))
			error(errno);
		error(errno);
	}

	pte_base = mmap(NULL, (size_t) (sizeof(void *))*pte_size,
		PROT_READ /*| PROT_WRITE*/,
		MAP_ANONYMOUS | MAP_SHARED,
			-1, 0);
	if (pte_base == NULL) {
		printf("ERROR: mmap returns NULL pte pointer\n");
		return 1;
	}
	if (pte_base == (void *) -1) {
		printf("pte could not map to mem\n");
		if (munmap(pgd_base, (size_t) (sizeof(void *))*pgd_size))
			error(errno);
		if (munmap(pmd_base, (size_t) (sizeof(void *))*pmd_size))
			error(errno);
		error(errno);
	}

	/* expose_page_table syscall */
	if (syscall(245, target_pid, (unsigned long) pgd_base,
		(unsigned long) pmd_base,
		(unsigned long) pte_base, begin_vaddr, end_vaddr)) {
		error(errno);
		if (munmap(pgd_base, (size_t) (sizeof(void *))*pgd_size))
			error(errno);
		if (munmap(pmd_base, (size_t) (sizeof(void *))*pmd_size))
			error(errno);
		if (munmap(pte_base, (size_t) (sizeof(void *))*pte_size))
			error(errno);
	}

/*	printf("PTE TABLE\n");
	print_pte(pte_base, pte_size);

	printf("PMD TABLE\n");
	print_pte(pmd_base, pmd_size);

	printf("PGD TABLE\n");
	print_pte(pgd_base, pgd_size);*/

	if (verb)
		ret_val = inspect(begin_vaddr, end_vaddr,
			pgd_base, dump_page_entry_verbose);
	else
		ret_val = inspect(begin_vaddr, end_vaddr,
			pgd_base, dump_page_entry);

	/* Check for segfault on write */
	/**((unsigned long *)pte_base) = 35;*/

	if (ret_val) {
		if (munmap(pgd_base, (size_t) (sizeof(void *))*pgd_size))
			error(errno);
		if (munmap(pmd_base, (size_t) (sizeof(void *))*pmd_size))
			error(errno);
		if (munmap(pte_base, (size_t) (sizeof(void *))*pte_size))
			error(errno);
		error(errno);
	}

	/* Unmapping */
	if (munmap(pgd_base, (size_t) (sizeof(void *))*pgd_size))
		error(errno);
	if (munmap(pmd_base, (size_t) (sizeof(void *))*pmd_size))
		error(errno);
	if (munmap(pte_base, (size_t) (sizeof(void *))*pte_size))
		error(errno);

	return 0;
}
