#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

// 页表缓存结构，用于减少重复查询
struct page_table_cache {
	uintptr_t last_va;        // 上次访问的虚拟地址
	phys_addr_t last_pa;      // 上次映射的物理地址
	size_t last_page_size;    // 上次映射的页大小
	bool valid;               // 缓存是否有效
};

// 静态缓存，减少频繁的页表查询
static struct page_table_cache read_cache = {0};
static struct page_table_cache write_cache = {0};

// 重置缓存
static inline void reset_cache(struct page_table_cache *cache) {
	cache->valid = false;
	cache->last_va = 0;
	cache->last_pa = 0;
	cache->last_page_size = 0;
}

// 使用缓存的虚拟地址到物理地址转换函数
static inline phys_addr_t cached_translate_linear_address(struct mm_struct* mm, uintptr_t va, struct page_table_cache *cache) {
	// 检查缓存是否命中
	if (cache->valid && 
		va >= cache->last_va && 
		va < cache->last_va + cache->last_page_size) {
		// 命中缓存，直接返回计算后的物理地址
		return cache->last_pa + (va - cache->last_va);
	}
	
	// 缓存未命中，执行完整的页表查找
	pgd_t *pgd;
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
	p4d_t *p4d;
	#endif
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	// 快速路径：避免不必要的条件判断和函数调用
	pgd = pgd_offset(mm, va);
	if(unlikely(pgd_none(*pgd) || pgd_bad(*pgd))) {
		reset_cache(cache);
		return 0;
	}
	
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
	p4d = p4d_offset(pgd, va);
	if(unlikely(p4d_none(*p4d) || p4d_bad(*p4d))) {
		reset_cache(cache);
		return 0;
	}
	pud = pud_offset(p4d, va);
	#else
	pud = pud_offset(pgd, va);
	#endif
	if(unlikely(pud_none(*pud) || pud_bad(*pud))) {
		reset_cache(cache);
		return 0;
	}
	
	pmd = pmd_offset(pud, va);
	if(unlikely(pmd_none(*pmd))) {
		reset_cache(cache);
		return 0;
	}
	
	// 直接获取物理页帧号和偏移量
	pte = pte_offset_kernel(pmd, va);
	if(unlikely(pte_none(*pte) || !pte_present(*pte))) {
		reset_cache(cache);
		return 0;
	}

	// 使用内联函数优化计算
	page_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	page_offset = va & (PAGE_SIZE - 1);
	phys_addr_t pa = page_addr + page_offset;
	
	// 更新缓存
	cache->valid = true;
	cache->last_va = va & PAGE_MASK;
	cache->last_pa = page_addr;
	cache->last_page_size = PAGE_SIZE;

	return pa;
}

// 公共接口函数 - 读操作使用读缓存
phys_addr_t translate_linear_address_read(struct mm_struct* mm, uintptr_t va) {
	return cached_translate_linear_address(mm, va, &read_cache);
}

// 公共接口函数 - 写操作使用写缓存
phys_addr_t translate_linear_address_write(struct mm_struct* mm, uintptr_t va) {
	return cached_translate_linear_address(mm, va, &write_cache);
}

// 为了保持向后兼容，保留原始函数接口
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
	return cached_translate_linear_address(mm, va, &read_cache);
}

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

// 批量物理内存读取优化
bool read_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	
	// 一次性映射整个内存区域
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	
	// 使用copy_to_user在内核空间和用户空间之间传输数据
	if (copy_to_user(buffer, mapped, size))
	{
		iounmap(mapped);
		return false;
	}
		iounmap(mapped);
	return true;
}

// 批量物理内存写入优化
bool write_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	
	// 一次性映射整个内存区域
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	
	// 使用copy_from_user在内核空间和用户空间之间传输数据
	if (copy_from_user(mapped, buffer, size))
	{
		iounmap(mapped);
		return false;
	}
		iounmap(mapped);
	return true;
}

// 进程内存读取优化 - 支持批量内存页处理
bool read_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;
	void *mapped_buffer = NULL;
	
	// 减少重复的pid查找开销
	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}

	// 对于大块内存的优化处理
	if (size > PAGE_SIZE * 4) {
		// 计算需要映射的连续页数
		uintptr_t page_start = addr & PAGE_MASK;
		uintptr_t page_end = (addr + size + PAGE_SIZE - 1) & PAGE_MASK;
		size_t map_size = page_end - page_start;
		uintptr_t offset = addr - page_start;
		
		// 一次性映射多页内存，使用读缓存
		pa = translate_linear_address_read(mm, page_start);
		if (pa) {
			// 使用缓存映射提高性能
			mapped_buffer = ioremap_cache(pa, map_size);
			if (mapped_buffer) {
				// 直接从映射的缓冲区复制数据到用户空间
				if (!copy_to_user(buffer, (char*)mapped_buffer + offset, size)) {
					result = true;
				}
				iounmap(mapped_buffer);
			}
		}
	} else {
		// 小块内存保持原有的高效处理，使用读缓存
		pa = translate_linear_address_read(mm, addr);
		if (pa) {
			result = read_physical_address(pa, buffer, size);
		} else {
			if (find_vma(mm, addr)) {
				if (clear_user(buffer, size) == 0) {
					result = true;
				}
			}
		}
	}

	mmput(mm);
	return result;
}

// 进程内存写入优化 - 支持批量内存页处理
bool write_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;
	void *mapped_buffer = NULL;
	
	// 减少重复的pid查找开销
	pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) {
		return false;
	}
	
	mm = get_task_mm(task);
	if (!mm) {
		return false;
	}

	// 对于大块内存的优化处理
	if (size > PAGE_SIZE * 4) {
		// 计算需要映射的连续页数
		uintptr_t page_start = addr & PAGE_MASK;
		uintptr_t page_end = (addr + size + PAGE_SIZE - 1) & PAGE_MASK;
		size_t map_size = page_end - page_start;
		uintptr_t offset = addr - page_start;
		
		// 一次性映射多页内存，使用写缓存
		pa = translate_linear_address_write(mm, page_start);
		if (pa) {
			// 使用缓存映射提高性能
			mapped_buffer = ioremap_cache(pa, map_size);
			if (mapped_buffer) {
				// 直接从用户空间复制数据到映射的缓冲区
				if (!copy_from_user((char*)mapped_buffer + offset, buffer, size)) {
					result = true;
				}
				iounmap(mapped_buffer);
			}
		}
	} else {
		// 小块内存保持原有的高效处理，使用写缓存
		pa = translate_linear_address_write(mm, addr);
		if (pa) {
			result = write_physical_address(pa, buffer, size);
		}
	}

	mmput(mm);
	return result;
}