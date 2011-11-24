/*
 * dsm_page_fault.h
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#ifndef DSM_PAGE_FAULT_H_
#define DSM_PAGE_FAULT_H_

#include <dsm/dsm_def.h>
#include <linux/swap.h>

#define DSM_PAGE_CACHE_PREFETCH      0               /* pages that were prefetched */

int page_is_in_dsm_cache(unsigned long);
int page_is_tagged_in_dsm_cache(unsigned long, int);

struct dsm_functions {
        struct subvirtual_machine *(*_find_svm)(struct dsm_vm_id *); //_find_svm;
        struct subvirtual_machine *(*_find_local_svm)(u16, struct mm_struct *); //_find_local_svm;
        int (*request_dsm_page)(struct page *, struct subvirtual_machine *,
                        struct subvirtual_machine *, uint64_t,
                        void(*func)(struct tx_buf_ele *));
};

// dsm_unmap
void reg_dsm_functions(
                struct subvirtual_machine *(*_find_svm)(struct dsm_vm_id *),
                struct subvirtual_machine *(*_find_local_svm)(u16,
                                struct mm_struct *),
                int(*request_dsm_page)(struct page *,
                                struct subvirtual_machine *,
                                struct subvirtual_machine *, uint64_t,
                                void(*func)(struct tx_buf_ele *)));
void dereg_dsm_functions(void);
int dsm_flag_page_remote(struct mm_struct *mm, struct dsm_vm_id id,
                unsigned long addr);

// dsm_page_request
struct page * dsm_extract_page_from_remote(struct dsm_message *);

// dsm_page_fault
int dsm_swap_wrapper(struct mm_struct *, struct vm_area_struct *, unsigned long,
                pte_t *, pmd_t *, unsigned int, pte_t, swp_entry_t);

extern struct dsm_functions *funcs;

#endif /* DSM_PAGE_FAULT_H_ */
