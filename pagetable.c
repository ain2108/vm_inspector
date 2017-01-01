#include <asm/unistd.h>
#include <asm/page.h> /* FOR PAGE_SHIFT, PMD_SHIFT, PGDIR_SHIFT */
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/mman.h>/*CHANGED FROM ASM*/
#include <linux/io.h>/*CHANGED FROM ASM
*/
#include "pagetable.h"

#define SIZE_PGD 512
#define SIZE_PMD 512
#define SIZE_PTE 512

#define RAMAP_SIZE 8

void fill_pagetable_layout_info(struct pagetable_layout_info *temp_info)
{

	temp_info->pgdir_shift = PGDIR_SHIFT;
	temp_info->pmd_shift = PMD_SHIFT;
	temp_info->page_shift = PAGE_SHIFT;
	return;
}

/* Find the task_struct by pid */
struct task_struct *get_task_struct_by_pid(pid_t pid)
{

	struct task_struct *to_audit_task;

	rcu_read_lock();
	to_audit_task = (pid == -1) ? current : find_task_by_vpid(pid);
	if (!to_audit_task) {
		rcu_read_unlock();
		return NULL;
	}
	get_task_struct(to_audit_task);
	rcu_read_unlock();


	return to_audit_task;
}

struct my_pte_args {
	unsigned long page_table_addr;
	struct vm_area_struct *our_vma;
	unsigned long fake_pmds;
	unsigned long fake_pgd;
	unsigned long init_fake_pmds;
};

int my_pmd_entry(pmd_t *pmd, unsigned long addr,
	unsigned long next,
	struct mm_walk *walk)
{

	struct my_pte_args *args;
	int retval;
	unsigned long *to;
	unsigned long banana;

	args = (struct my_pte_args *) walk->private;

	/* Lock the semaphore as suggested in the doc */
	down_write(&current->active_mm->mmap_sem);

	/* Remap the pte, make sure it succeeds */
	retval = remap_pfn_range(args->our_vma,
		args->page_table_addr,
		pmd_val(*pmd) >> PAGE_SHIFT,
		PAGE_SIZE,
		args->our_vma->vm_page_prot);
	if (retval) {
		up_write(&current->active_mm->mmap_sem);
		return -EFAULT;
	}

	/* Make sure we are writing into correct pmd entry */
	args->fake_pmds = pgd_index(addr)*8*SIZE_PMD + args->init_fake_pmds;
	banana = args->page_table_addr;
	to = (void *) (args->fake_pmds +
		pmd_index(addr)*8);
	retval = copy_to_user(to, &banana, 8);
	if (retval) {
		up_write(&current->active_mm->mmap_sem);
		return -EFAULT;
	}

	/* Let go of the semaphore since we are done here */
	up_write(&current->active_mm->mmap_sem);

	/* Increment the page_table_addr to write to correct entries */
	args->page_table_addr += PAGE_SIZE;
	return 0;
}

int fix_pgd(unsigned long fake_pgd, unsigned long fake_pmds)
{

	int i;
	int retval;
	unsigned long *to;
	unsigned long banana;

	for (i = 0; i < SIZE_PGD; i++) {

		banana = fake_pmds + (i * PTRS_PER_PMD * sizeof(void *));
		to = (void *) (fake_pgd + i*sizeof(void *));

		retval = copy_to_user(to, &banana, sizeof(void *));
		if (retval)
			return retval;
	}

	return 0;
}


int ramapper_using_pagewalk(struct vm_area_struct *our_vma,
	struct mm_struct *to_audit_mm,
	unsigned long page_table_addr,
	unsigned long begin_vaddr,
	unsigned long end_vaddr,
	unsigned long fake_pmds,
	unsigned long fake_pgd)
{
	int retval;

	struct my_pte_args args = {
		.page_table_addr	= page_table_addr,
		.fake_pmds			= fake_pmds,
		.init_fake_pmds		= fake_pmds,
		.our_vma			= our_vma,
		.fake_pgd			= fake_pgd
	};

	struct mm_walk walk = {
		.pmd_entry			= my_pmd_entry,
		.mm					= to_audit_mm,
		.private			= &args
	};

	spin_lock(&to_audit_mm->page_table_lock);

	retval = fix_pgd(fake_pgd, fake_pmds);

	if (retval) {
		spin_unlock(&to_audit_mm->page_table_lock);
		return retval;
	}

	/* The walk will populate pmd's and remap the pte's */
	retval = walk_page_range(begin_vaddr, end_vaddr, &walk);
	if (retval) {
		spin_unlock(&to_audit_mm->page_table_lock);
		return retval;
	}

	spin_unlock(&to_audit_mm->page_table_lock);

	return 0;

}

/* Will check if the passed vaddresses make sense */
int check_vaddr(unsigned long begin_vaddr, unsigned long end_vaddr)
{
	if (begin_vaddr % PAGE_SIZE)
		return -EFAULT;
	if (end_vaddr % PAGE_SIZE)
		return -EFAULT;
	if (begin_vaddr > end_vaddr)
		return -EFAULT;

	return 0;
}


SYSCALL_DEFINE6(expose_page_table, pid_t, pid,
			unsigned long, fake_pgd,
			unsigned long, fake_pmds,
			unsigned long, page_table_addr,
			unsigned long, begin_vaddr,
			unsigned long, end_vaddr)
{

	struct task_struct *to_audit_task;
	struct mm_struct *to_audit_mm;
	struct mm_struct *our_mm;
	struct vm_area_struct *our_vma;
	int retval;
	unsigned long our_vma_size;
	unsigned long vaddr_range;


	/* Check if passed addresses are aligned
	   and correct numerically */
	retval = check_vaddr(begin_vaddr, end_vaddr);
	if (retval)
		return retval;


	/* Get the task struct of the target process */
	to_audit_task = get_task_struct_by_pid(pid);
	if (to_audit_task == NULL) {
		/*printk(KERN_ERR"get_task_struct_by_pid returned NULL\n");*/
		return -ESRCH;
	}

	/* Targets mm */
	to_audit_mm = to_audit_task->mm;
	our_mm = current->active_mm;

	if(current == to_audit_task){
		printk(KERN_ERR"hello ==\n");
		to_audit_mm = to_audit_task->active_mm;
	}

	our_vma = find_vma(our_mm, page_table_addr); /* TODO: buffix */
	if (our_vma == NULL) {
		put_task_struct(to_audit_task);
		return -EINVAL;
	}

	our_vma_size = our_vma->vm_end - our_vma->vm_start;
	vaddr_range = ((end_vaddr - begin_vaddr) / PAGE_SIZE) + 2;

	if (our_vma_size < vaddr_range) {
		/*printk(KERN_ERR"vma too small for this range\n");*/
		return -EINVAL;
	}

	/* Main reoutine. Will traverse the tables, remap ptes, fillin
	   the pmds and pgds */
	retval = ramapper_using_pagewalk(our_vma, to_audit_mm,
		page_table_addr, begin_vaddr,
		end_vaddr, fake_pmds, fake_pgd);

	put_task_struct(to_audit_task);

	if (retval)
		return retval;

	return 0;
}

SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *,
				pgtbl_info, int, size)
{
	struct pagetable_layout_info temp_info;

	if (size < (sizeof(struct pagetable_layout_info))) {
		/*printk(KERN_ERR"SIZE TOO SMALL");*/
		return -EINVAL;
	}

	fill_pagetable_layout_info(&temp_info);

	if (copy_to_user(pgtbl_info, &temp_info,
		sizeof(struct pagetable_layout_info)))
		return -EFAULT;

	return 0;
}
