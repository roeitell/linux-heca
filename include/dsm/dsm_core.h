/*
 * dsm_page_fault.h
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#ifndef DSM_PAGE_FAULT_H_
#define DSM_PAGE_FAULT_H_

#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/page-flags.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_context.h>
#include <linux/init.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <asm-generic/memory_model.h>
#include <asm-generic/mman-common.h>

#include "../../../mm/internal.h"

#include <dsm/dsm_def.h>

#define PREFETCH_TAG    0
#define TRY_TAG         1
#define PULL_TAG        2               /* pages that we try to get pulled */
#define DEFAULT_TAG    RADIX_TREE_MAX_TAGS


struct page *page_is_in_dsm_cache(unsigned long);
int page_is_tagged_in_dsm_cache(unsigned long, int);
int add_page_pull_to_dsm_cache(struct page *, unsigned long, gfp_t);
int delete_from_dsm_cache(struct page *, unsigned long);
struct page *find_get_dsm_page(unsigned long);

struct dsm_functions {
    struct subvirtual_machine *(*_find_svm)(struct dsm_vm_id *); //_find_svm;
    struct subvirtual_machine *(*_find_local_svm)(u16, struct mm_struct *); //_find_local_svm;
    int (*request_dsm_page)(struct page *, struct subvirtual_machine *,
            struct subvirtual_machine *, uint64_t,
            void(*func)(struct tx_buf_ele *), int);
};

// dsm_unmap
void reg_dsm_functions(
        struct subvirtual_machine *(*_find_svm)(struct dsm_vm_id *),
        struct subvirtual_machine *(*_find_local_svm)(u16, struct mm_struct *),
        int(*request_dsm_page)(struct page *, struct subvirtual_machine *,
                struct subvirtual_machine *, uint64_t,
                void(*func)(struct tx_buf_ele *), int));
void dereg_dsm_functions(void);
int dsm_flag_page_remote(struct mm_struct *mm, struct dsm_vm_id id,
        unsigned long addr);

// dsm_page_request
struct page * dsm_extract_page_from_remote(struct dsm_message *);

// dsm_page_fault
int dsm_try_push_page(struct mm_struct *, struct dsm_vm_id, unsigned long);

extern struct dsm_functions *funcs;
struct page *dsm_trigger_page_pull(struct dsm_message *);

#endif /* DSM_PAGE_FAULT_H_ */
