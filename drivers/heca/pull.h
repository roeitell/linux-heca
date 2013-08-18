#ifndef _HECA_PULL_H
#define _HECA_PULL_H

#include <linux/mm_types.h>

#include "struct.h"

#define PULL_TAG        (1 << 0)  /* pulling the page */
#define PREFETCH_TAG    (1 << 1)  /* pulling the page for prefetch */
#define PUSH_TAG        (1 << 2)  /* pushing the page */
#define PULL_TRY_TAG    (1 << 3)  /* pulling the page by request */
#define CLAIM_TAG       (1 << 4)  /* reclaiming a page */
#define READ_TAG        (1 << 5)  /* pulling the page for read */

int heca_initiate_fault(struct mm_struct *, unsigned long, int);
void init_heca_prefetch_cache_kmem(void);
void destroy_heca_prefetch_cache_kmem(void);
int heca_zero_pfn_init(void);
void heca_zero_pfn_exit(void);
inline void heca_release_pull_hpc(struct heca_page_cache **);
void dequeue_and_gup_cleanup(struct heca_process *);
void delayed_gup_work_fn(struct work_struct *);
int heca_pull_req_failure(struct heca_page_cache *);
int heca_swap_wrapper(struct mm_struct *, struct vm_area_struct *,
                unsigned long, pte_t *, pmd_t *, unsigned int, pte_t,
                swp_entry_t);
int heca_trigger_page_pull(struct heca_space *, struct heca_process *,
                struct heca_memory_region *, unsigned long);
int heca_write_fault(struct mm_struct *, struct vm_area_struct *,
                unsigned long, pmd_t *, pte_t *, spinlock_t *, unsigned int);

#endif /* _HECA_PULL_H */

