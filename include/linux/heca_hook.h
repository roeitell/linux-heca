/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 */

#ifndef HECA_HOOK_H_
#define HECA_HOOK_H_

#include <linux/mm.h>
#include <linux/swap.h>

typedef int (*fetch_page_cb)(struct mm_struct *, struct vm_area_struct *,
    unsigned long, pte_t *, pmd_t *, unsigned int, pte_t, swp_entry_t);

typedef int (*pushback_page_cb)(struct page *);

typedef int (*is_congested_cb)(void);

typedef int (*detach_task_cb)(struct task_struct *tsk);

typedef int (*attach_task_cb)(struct task_struct *tsk);

struct heca_hook_struct {
    const char *name;
    fetch_page_cb fetch_page;
    pushback_page_cb pushback_page;
    is_congested_cb is_congested;
    detach_task_cb detach_task;
    attach_task_cb attach_task;
};

const struct heca_hook_struct *heca_hook_read(void);
void heca_hook_release(const struct heca_hook_struct *hook);
int heca_hook_register(const struct heca_hook_struct *hook);
int heca_hook_unregister(void);
#endif /* HECA_HOOK_H_ */

