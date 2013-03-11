#ifndef _HECA_PULL_H
#define _HECA_PULL_H

#include <linux/mm_types.h>

#include "struct.h"

#define PULL_TAG        (1 << 0)  /* pulling the page */
#define PREFETCH_TAG    (1 << 1)  /* pulling the page for prefetch */
#define PUSH_TAG        (1 << 2)  /* pushing the page */
#define PULL_TRY_TAG    (1 << 3)  /* pulling the page by request */
#define CLAIM_TAG       (1 << 4)  /* reclaiming a page */

int dsm_initiate_fault(struct mm_struct *, unsigned long, int);
void init_dsm_prefetch_cache_kmem(void);
void destroy_dsm_prefetch_cache_kmem(void);
int dsm_zero_pfn_init(void);
void dsm_zero_pfn_exit(void);
inline void dsm_release_pull_dpc(struct dsm_page_cache **);
void dequeue_and_gup_cleanup(struct subvirtual_machine *);
void delayed_gup_work_fn(struct work_struct *);
int dsm_pull_req_failure(struct dsm_page_cache *);
int dsm_swap_wrapper(struct mm_struct *, struct vm_area_struct *,
        unsigned long, pte_t *, pmd_t *, unsigned int, pte_t,
        swp_entry_t);
int dsm_trigger_page_pull(struct dsm *, struct subvirtual_machine *,
        struct memory_region *, unsigned long);

#endif /* _HECA_PULL_H */

