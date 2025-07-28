#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _proinf{
    uintptr_t cmaddr;
    uintptr_t mbaddr;
    uintptr_t isreadaddr;
    int isread;
}proinf, *PCOPY_proinf;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);
