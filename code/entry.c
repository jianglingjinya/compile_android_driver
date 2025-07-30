#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg)
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

struct file_operations dispatch_functions = {
	.owner  = THIS_MODULE,
	.open	= dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct mem_tool_device {
	struct cdev cdev;
	struct device *dev;
	int max;
};

static struct mem_tool_device *memdev;
static struct list_head *prev_module;
static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

int dispatch_open(struct inode *node, struct file *file)
{
	file->private_data = memdev;
	prev_module = __this_module.list.prev;
	list_del_init(&__this_module.list); 
	device_destroy(mem_tool_class, mem_tool_dev_t); 
	class_destroy(mem_tool_class); 
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	list_add(&__this_module.list, prev_module); 
	mem_tool_class = class_create(THIS_MODULE, devicename); 
	memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename); 
	return 0;
}

// 清除模块的符号表
static void hide_module_symbols(struct module *mod) {
    mod->num_symtab = 0;
    mod->symtab = NULL;
    mod->strtab = NULL;
}

// 移除模块的sect_attrs（节区属性）
static void hide_sect_attrs(struct module *mod) {
    if (mod->sect_attrs) {
        sysfs_remove_group(&mod->mkobj.kobj, &mod->sect_attrs->grp);
        kfree(mod->sect_attrs);
        mod->sect_attrs = NULL;
    }
}

// 清除模块的notes段
static void hide_module_notes(struct module *mod) {
    mod->notes_attrs = NULL;
    mod->num_notes = 0;
}

// 清除模块参数
static void hide_module_params(struct module *mod) {
    mod->num_kp = 0;
    mod->kp = NULL;
}

// 禁用模块的tracepoints
static void disable_tracepoints(struct module *mod) {
#ifdef CONFIG_TRACEPOINTS
    mod->num_tracepoints = 0;
    mod->tracepoints_ptrs = NULL;
#endif
}

// 清除模块的bug表
static void hide_bug_table(struct module *mod) {
    mod->bug_table = NULL;
    mod->num_bugs = 0;
}

// 清除GPL-only依赖标记
static void hide_gpl_only_symbols(struct module *mod) {
    mod->gpl_compatible = 1;
}

static int __init driver_entry(void)
{
	int ret;
	devicename = DEVICE_NAME;
	devicename = get_rand_str();

	ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
	if (ret < 0) {
		return ret;
	}

	memdev = kmalloc(sizeof(struct mem_tool_device), GFP_KERNEL);
	if (!memdev) {
		goto done;
	}
	memset(memdev, 0, sizeof(struct mem_tool_device));

	cdev_init(&memdev->cdev, &dispatch_functions); 
	memdev->cdev.owner = THIS_MODULE; 
	memdev->cdev.ops = &dispatch_functions; 

	ret = cdev_add(&memdev->cdev, mem_tool_dev_t, 1);
	if (ret) {
		goto done;
	}

	mem_tool_class = class_create(THIS_MODULE, devicename); 
	if (IS_ERR(mem_tool_class)) {
		goto done;
	}
	memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename); 
	if (IS_ERR(memdev->dev)) {
		goto done;
	}

	unregister_chrdev_region(mem_tool_dev_t, 1); 
	kobject_del(&THIS_MODULE->mkobj.kobj); 
    list_del(&THIS_MODULE->mkobj.kobj.entry);

    hide_module_symbols(THIS_MODULE);
    hide_sect_attrs(THIS_MODULE);
    hide_module_notes(THIS_MODULE);
    hide_module_params(THIS_MODULE);
    disable_tracepoints(THIS_MODULE);
    hide_bug_table(THIS_MODULE);
    hide_gpl_only_symbols(THIS_MODULE);    
        
	return 0;

done:
	return ret;
}

static void __exit driver_unload(void)
{
	device_destroy(mem_tool_class, mem_tool_dev_t); 
	class_destroy(mem_tool_class); 

	cdev_del(&memdev->cdev); 
	kfree(memdev);
	unregister_chrdev_region(mem_tool_dev_t, 1); 
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("盼盼食品");