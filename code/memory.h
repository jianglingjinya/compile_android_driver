#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}

	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);

	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}

	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);

	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif

#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static size_t get_high_memory(void)
{
	struct sysinfo meminfo;
	si_meminfo(&meminfo);
	return (meminfo.totalram * (meminfo.mem_unit / 1024)) << PAGE_SHIFT;
}
#define valid_phys_addr_range(addr, count) (addr + count <= get_high_memory())
#else
#define valid_phys_addr_range(addr, count) true
#endif

static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size)
{
    void *mapped_addr;
    size_t bytes_read = 0;
    size_t current_size;
    unsigned long current_pa = pa;

    if (!size || !pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }

    if (!valid_phys_addr_range(pa, size)) {
        return false;
    }

    while (bytes_read < size) {
        current_size = size - bytes_read;

        mapped_addr = ioremap_cache(current_pa, current_size);
        if (!mapped_addr) {
            return false;
        }

        if (copy_to_user(buffer + bytes_read, mapped_addr, current_size)) {
            iounmap(mapped_addr);
            return false;
        }

        iounmap(mapped_addr);
        bytes_read += current_size;
        current_pa += current_size;
    }

    return true;
}

static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size)
{
    void *mapped_addr;
    size_t bytes_written = 0;
    size_t current_size;
    unsigned long current_pa = pa;

    if (!size || !pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }

    if (!valid_phys_addr_range(pa, size)) {
        return false;
    }

    while (bytes_written < size) {
        current_size = size - bytes_written;

        mapped_addr = ioremap_cache(current_pa, current_size);
        if (!mapped_addr) {
            return false;
        }

        if (copy_from_user(mapped_addr, buffer + bytes_written, current_size)) {
            iounmap(mapped_addr);
            return false;
        }

        iounmap(mapped_addr);
        bytes_written += current_size;
        current_pa += current_size;
    }

    return true;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    size_t bytes_read = 0;
    size_t remaining = size;
    size_t chunk_size;

    if (!size || !buffer)
        return false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    mm = get_task_mm(task);
    if (!mm)
        return false;


    while (remaining > 0) {
        chunk_size = min_t(size_t, remaining, PAGE_SIZE - (addr & ~PAGE_MASK));
        
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            goto out_error;
        }

        if (!read_physical_address(pa, (void __user *)(buffer + bytes_read), chunk_size)) {
            goto out_error;
        }

        bytes_read += chunk_size;
        remaining -= chunk_size;
        addr += chunk_size;
    }

    mmput(mm);
    return true;

out_error:
    mmput(mm);
    return false;
}

bool write_process_memory(pid_t pid, uintptr_t addr, const void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    size_t bytes_written = 0;
    size_t remaining = size;
    size_t chunk_size;

    if (!size || !buffer)
        return false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    mm = get_task_mm(task);
    if (!mm)
        return false;


    while (remaining > 0) {
        chunk_size = min_t(size_t, remaining, PAGE_SIZE - (addr & ~PAGE_MASK));
        
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            goto out_error;
        }

        if (!write_physical_address(pa, (const void __user *)(buffer + bytes_written), chunk_size)) {
            goto out_error;
        }

        bytes_written += chunk_size;
        remaining -= chunk_size;
        addr += chunk_size;
    }

    mmput(mm);
    return true;

out_error:
    mmput(mm);
    return false;
}