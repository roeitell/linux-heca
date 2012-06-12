/*
 * dsm_mem.h
 *
 *  Created on: 14 Dec 2011
 *      Author: Benoit
 */

#ifndef DSM_MEM_H_
#define DSM_MEM_H_

#include <linux/mm.h>
#include <linux/swap.h>
/*
 * memory c hook
 *
 */
int dsm_swap_wrapper(struct mm_struct *, struct vm_area_struct *, unsigned long,
        pte_t *, pmd_t *, unsigned int, pte_t, swp_entry_t);

/*
 * VM scan hook for swap push back
 */
int push_back_if_remote_dsm_page(struct page *);

#endif /* DSM_MEM_H_ */
