/*
 * dsm_page_fault.h
 *
 *  Created on: 1 Aug 2011
 *      Author: Benoit
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

#define DSM_PAGE_CACHE_DEFAULT  4 /* default alloc of pages in cache */

#define PULL_TAG        1  /* pulling the page */
#define PREFETCH_TAG    2  /* pulling the page for prefetch */
#define PUSH_TAG        4  /* pushing the page */
#define PULL_TRY_TAG    8  /* pulling the page by request (pushing to us) */


/* dsm_cache.c */
void init_dsm_cache_kmem(void);
void destroy_dsm_cache_kmem(void);
struct dsm_page_cache *dsm_cache_add(struct subvirtual_machine *, unsigned long,
       int, int, int);
struct dsm_page_cache_lookup dsm_cache_add_page(struct subvirtual_machine *,
        unsigned long, int, int, int, struct vm_area_struct *);
struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine*, unsigned long);
struct dsm_page_cache *dsm_cache_get_hold(struct subvirtual_machine*,
        unsigned long);
struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *, 
        unsigned long);
struct dsm_page_cache *dsm_alloc_dpc(int, int, int, struct subvirtual_machine*);
void dsm_dealloc_dpc(struct dsm_page_cache **);


struct dsm_functions {
    struct dsm *(*_find_dsm)(u32 dsm_id);

    struct subvirtual_machine *(*_find_svm)(struct dsm *, u32 svm_id);

    struct subvirtual_machine *(*_find_local_svm)(struct dsm *,
            struct mm_struct *);

    int (*request_dsm_page)(struct page *, struct subvirtual_machine *, 
            struct subvirtual_machine *, uint64_t, 
            void(*func)(struct tx_buf_ele *), int, struct dsm_page_cache *);
};

// dsm_unmap
void reg_dsm_functions(
    struct dsm *(*_find_dsm)(u32 dsm_id),

    struct subvirtual_machine *(*_find_svm)(struct dsm* dsm, u32 svm_id),

    struct subvirtual_machine *(*_find_local_svm)(struct dsm *,
                struct mm_struct *),

    int(*request_dsm_page)(struct page *, struct subvirtual_machine *, 
        struct subvirtual_machine *, uint64_t, 
        void(*func)(struct tx_buf_ele *), int, struct dsm_page_cache*)
);

void dereg_dsm_functions(void);
int dsm_flag_page_remote(struct mm_struct *, struct dsm *, u32,
        unsigned long);

// dsm_page_request
struct page * dsm_extract_page_from_remote(struct dsm *, 
        struct subvirtual_machine *, struct subvirtual_machine *, unsigned long,
        u16);

// dsm_page_fault
int dsm_try_push_page(struct dsm *, struct subvirtual_machine *, 
    struct mm_struct *, u32, int, unsigned long);

extern struct dsm_functions *funcs;
struct dsm_page_cache *dsm_trigger_page_pull(struct dsm *, 
        struct subvirtual_machine *, unsigned long);

// svm_descriptors
void dsm_init_descriptors(void);
void dsm_destroy_descriptors(void);
swp_entry_t dsm_descriptor_to_swp_entry(u32, u32);
struct svm_list dsm_descriptor_to_svms(u32);
struct dsm_swp_data swp_entry_to_dsm_data(swp_entry_t);
u32 dsm_get_descriptor(struct dsm *, u32 *);

#endif /* DSM_PAGE_FAULT_H_ */
