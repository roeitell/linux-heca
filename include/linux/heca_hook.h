/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 */

#ifndef DSM_HOOK_H_
#define DSM_HOOK_H_

#include <linux/mm.h>
#include <linux/swap.h>

typedef int (*fetch_page_cb)(struct mm_struct *, struct vm_area_struct *,
    unsigned long, pte_t *, pmd_t *, unsigned int, pte_t, swp_entry_t);

typedef int (*pushback_page_cb)(struct page *);

typedef int (*is_congested_cb)(void);

struct dsm_hook_struct {
    const char *name;
    fetch_page_cb fetch_page;
    pushback_page_cb pushback_page;
    is_congested_cb is_congested;
};

const struct dsm_hook_struct *dsm_hook_read(void);
void dsm_hook_write(const struct dsm_hook_struct *hook);
#endif /* DSM_HOOK_H_ */

