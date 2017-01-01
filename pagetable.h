#ifndef _PAGETABLE_H_
#define _PAGETABLE_H_

#include <linux/types.h>

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

void fill_pagetable_layout_info(struct pagetable_layout_info *temp_info);
int ramapper_using_pagewalk(struct vm_area_struct *our_vma,
			struct mm_struct *to_audit_mm,
			unsigned long page_table_addr,
			unsigned long begin_vaddr,
			unsigned long end_vaddr,
			unsigned long fake_pmds,
			unsigned long fake_pgd);

#endif
