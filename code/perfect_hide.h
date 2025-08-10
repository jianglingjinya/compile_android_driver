#ifndef PERFECT_HIDE_H
#define PERFECT_HIDE_H

#include <linux/types.h>

struct perfect_req {
    pid_t pid;
    uintptr_t addr;
    size_t  len;
};

#endif
