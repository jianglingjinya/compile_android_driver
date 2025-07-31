#include <linux/slab.h>
#include <linux/random.h>

#define DEVICE_NAME "Mask"

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

enum OPERATIONS {
    OP_INIT_KEY = 0x9000,
    OP_READ_MEM = 0x9001,
    OP_WRITE_MEM = 0x9002,
    OP_MODULE_BASE = 0x9003,
};

char* get_rand_str(void)
{
	static char string[31];
	int lstr,seed,flag,i;
	char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	lstr = strlen(str);
	for (i = 0; i < 30; i++)
	{
		get_random_bytes(&seed, sizeof(int));
		flag = seed % lstr;
		if (flag < 0)
			flag = flag * -1;
		string[i] = str[flag];
	}
	string[30] = '\0';
	return string;
}

int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);