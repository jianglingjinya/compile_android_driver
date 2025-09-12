#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,43))
#include <linux/mmap_lock.h>
#define mm_read_lock(mm) mmap_read_lock(mm);
#define mm_read_unlock(mm) mmap_read_unlock(mm);
#else
#include <linux/rwsem.h>
#define mm_read_lock(mm) down_read(&(mm)->mmap_sem);
#define mm_read_unlock(mm) up_read(&(mm)->mmap_sem);
#endif

int get_task_cmdline(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	unsigned long arg_start, arg_end, env_start, env_end;
	if (!mm)
	    goto out;
	if (!mm->arg_end)
		goto out_mm;
		
	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
	spin_unlock(&mm->arg_lock);

	len = arg_end - arg_start;

	if (len > buflen)
		len = buflen;

	res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

	if (res > 0 && buffer[res-1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = env_end - env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += access_process_vm(task, env_start,
						 buffer+res, len,
						 FOLL_FORCE);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}

pid_t get_process_pid(char *name)
{
    int ret;
    pid_t pid = -1;
    char *cmdline;
    size_t name_len;
    struct task_struct *task;

    if (!name || !*name) {
        goto out;
    }

    name_len = strlen(name);
    if (name_len == 0 || name_len >= PATH_MAX) {
        goto out;    
    }

    cmdline = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!cmdline) {
        goto out;
    }
    
    rcu_read_lock();
    for_each_process(task) {
        if (!task->mm)
            continue;

        ret = get_task_cmdline(task, cmdline, PATH_MAX);
        if (ret > 0) {
            if (strcmp(cmdline, name) == 0) {
                pid = task->pid;
                break;
            }
        }
    }
    rcu_read_unlock();
    kfree(cmdline);

out:    
    return pid;
}

uintptr_t get_module_base(pid_t pid, char* name)
{
	char *path;
	char *pathname;
    struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	size_t base = 0;

    rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
	    rcu_read_unlock();
		goto out;
	}
    rcu_read_unlock();
    
	mm = get_task_mm(task);
	if (!mm) {
		goto out;
	}

    pathname = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pathname) {
        goto out_mm;
    }
    
    mm_read_lock(mm);
    while (true) {
        vma = find_vma(mm, base);        
        if (vma->vm_file) {
			if ((vma->vm_flags & (VM_READ | VM_EXEC))) {
    		    path = d_path(&vma->vm_file->f_path, pathname, PATH_MAX);
    			if (!IS_ERR(path) && !strcmp(kbasename(path), name)) {
                    base = vma->vm_start;
    				break;
    		    }
			}
        }
		if (vma->vm_end >= ULONG_MAX) break;
		base = (uintptr_t)vma->vm_end;
    }
    mm_read_unlock(mm);
    kfree(pathname);
    
out_mm:
	mmput(mm);
out:
	return base;
}
