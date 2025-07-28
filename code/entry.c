#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#define OP_CMD_READ 0x1001
#define OP_CMD_WRITE 0x1002
#define OP_CMD_BASE 0x1003

long handle_ioctl(unsigned int fd, unsigned int const cmd, unsigned long const arg)
{
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static char name[0x100] = {0};
	
	switch (cmd) {
		case OP_READ_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;
		case OP_WRITE_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;
		case OP_MODULE_BASE:
			{
				if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
				|| copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
					return -1;
				}
				mb.base = get_module_base(mb.pid, name);
				if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
					return -1;
				}
			}
			break;
		default:
			break;
	}
	return 0;
}

static int handler_ioctl_pre(struct kprobe *p, struct pt_regs *kregs)
{
    unsigned int fd = (unsigned int)kregs->regs[0];
    unsigned int cmd = (unsigned int)kregs->regs[1];
    unsigned long arg = (unsigned long)kregs->regs[2];
    if (fd==-1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE)
    {
        handle_ioctl(fd, cmd, arg);
        return 1;
    }

    return 0;
}

/*static int handler_ioctl_pre(struct kprobe *p, struct pt_regs *kregs)
{
    unsigned int cmd = (unsigned int)kregs->regs[1];
    unsigned long arg = (unsigned long)kregs->regs[2];
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    if (cmd >= OP_CMD_READ && cmd <= OP_CMD_BASE)
    {
        switch(cmd)
        {
            case OP_CMD_READ:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return 0;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return 0;
                }
                break;
            case OP_CMD_WRITE:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return 0;
                }
                if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return 0;
                }
                break;
            case OP_CMD_BASE:
                if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
                    return 0;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) {
                      return 0;
                }
                break;
            default:
                break;
        }
    }
    return 0;
}*/

static struct kprobe kp = {
    .symbol_name = "inet_ioctl",
    .pre_handler = handler_ioctl_pre,
    //kp.symbol_name = "__arm64_sys_lookup_dcookie";// hooksyscall方案
    //kp.pre_handler = handler_pre;
};

static int __init my_module_init(void) {
    if (register_kprobe(&kp) < 0) {
        return -1;
    }

	list_del(&THIS_MODULE->list); 
    kobject_del(&THIS_MODULE->mkobj.kobj); 
    list_del(&THIS_MODULE->mkobj.kobj.entry);
        
    return 0;
}

static void __exit my_module_exit(void) {
    unregister_kprobe(&kp);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("盼盼食品");