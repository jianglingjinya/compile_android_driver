#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/pid.h>

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
	struct task_struct *task;
	struct pid *pid_struct;
	int bytes_read;
	void *kbuf;

	if (size == 0 || size > (1024 * 1024)) 
		return false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return false;

	kbuf = kmalloc(size, GFP_KERNEL);
	if (!kbuf) {
		put_task_struct(task);
		return false;
	}

	bytes_read = access_process_vm(task, addr, kbuf, size, FOLL_FORCE);
	put_task_struct(task);

	if (bytes_read != size) {
		kfree(kbuf);
		return false;
	}

	if (copy_to_user(buffer, kbuf, size)) {
		kfree(kbuf);
		return false;
	}

	kfree(kbuf);
	return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
	struct task_struct *task;
	struct pid *pid_struct;
	int bytes_written;
	void *kbuf;

	if (size == 0 || size > (1024 * 1024)) 
		return false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return false;

	kbuf = kmalloc(size, GFP_KERNEL);
	if (!kbuf) {
		put_task_struct(task);
		return false;
	}

	if (copy_from_user(kbuf, buffer, size)) {
		kfree(kbuf);
		put_task_struct(task);
		return false;
	}

	bytes_written = access_process_vm(task, addr, kbuf, size, FOLL_FORCE | FOLL_WRITE);
	put_task_struct(task);
	kfree(kbuf);

	return (bytes_written == size);
}
