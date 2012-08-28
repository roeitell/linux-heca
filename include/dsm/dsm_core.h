/*
 * dsm_page_fault.h
 *
 *  Created on: 1 Aug 2011
 *      Author: Benoit Hudzia
 */

#ifndef DSM_CORE_H_
#define DSM_CORE_H_

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
#include <linux/atomic.h>
#include <linux/wait.h>

#include <asm-generic/memory_model.h>
#include <asm-generic/mman-common.h>

#include "../../../mm/internal.h"

#include <dsm/dsm_def.h>

#define PULL_TAG        (1 << 0)  /* pulling the page */
#define PREFETCH_TAG    (1 << 1)  /* pulling the page for prefetch */
#define PUSH_TAG        (1 << 2)  /* pushing the page */
#define PULL_TRY_TAG    (1 << 3)  /* pulling the page by request (pushing to us) */

#define for_each_valid_svm(svms, i)         \
    for (i = 0; i < (svms).num; i++)        \
        if (likely((svms).pp[i]))



/* dsm_search */
inline int dsm_swp_entry_same(swp_entry_t, swp_entry_t);
int swp_entry_to_dsm_data(swp_entry_t, struct dsm_swp_data *);
inline swp_entry_t dsm_descriptor_to_swp_entry(u32, u32);
inline pte_t dsm_descriptor_to_pte(u32, u32);
inline void release_svm(struct subvirtual_machine *);

/* dsm_cache.c */
struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *,
        unsigned long);
void init_dsm_cache_kmem(void);
void destroy_dsm_cache_kmem(void);
struct dsm_page_cache *dsm_cache_get_hold(struct subvirtual_machine *,
        unsigned long);
struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *,
        unsigned long);
struct dsm_page_cache *dsm_alloc_dpc(struct subvirtual_machine *, unsigned long,
        struct svm_list, int, int);
void dsm_dealloc_dpc(struct dsm_page_cache **);
int dsm_init_page_pool(struct conn_element *);
void dsm_destroy_page_pool(struct conn_element *);
struct page_pool_ele *dsm_fetch_ready_ppe(struct conn_element *);
struct page_pool_ele *dsm_prepare_ppe(struct conn_element *, struct page *);
void dsm_ppe_clear_release(struct conn_element *, struct page_pool_ele **);

int dsm_request_page_pull(struct dsm *, struct subvirtual_machine *,
        struct page *, unsigned long, struct mm_struct *,
        struct memory_region *);

/* dsm_page_request.c */
struct page *dsm_extract_page_from_remote(struct subvirtual_machine *,
        struct subvirtual_machine *, unsigned long, u16, pte_t **, u32 *, int);
int dsm_prepare_page_for_push(struct subvirtual_machine *, struct svm_list,
        struct page *, unsigned long, struct mm_struct *, u32);
struct page *dsm_find_normal_page(struct mm_struct *, unsigned long);
int dsm_cancel_page_push(struct subvirtual_machine *, unsigned long,
        struct page *);
struct dsm_page_cache *dsm_push_cache_get_remove(struct subvirtual_machine *,
        unsigned long);
void dsm_push_finish_notify(struct page *);
void dsm_push_cache_release(struct subvirtual_machine *,
        struct dsm_page_cache **, int);
int dsm_is_congested(void);

/* dsm_unmap.c */
int dsm_flag_page_remote(struct mm_struct *mm, struct dsm *dsm, u32 descriptor,
        unsigned long request_addr);

/* dsm_page_fault.c */
void dequeue_and_gup_cleanup(struct subvirtual_machine *);
void dequeue_and_gup(struct subvirtual_machine *);
void delayed_gup_work_fn(struct work_struct *);
void init_dsm_prefetch_cache_kmem(void);
void destroy_dsm_prefetch_cache_kmem(void) ;
int dsm_trigger_page_pull(struct dsm *, struct subvirtual_machine *,
        struct memory_region *, unsigned long);
void dsm_release_pull_dpc(struct dsm_page_cache **);
int dsm_pull_req_failure(struct dsm_page_cache *);

/* svm_descriptors */
void dsm_init_descriptors(void);
void dsm_destroy_descriptors(void);
swp_entry_t dsm_descriptor_to_swp_entry(u32, u32);
struct svm_list dsm_descriptor_to_svms(u32);
u32 dsm_get_descriptor(struct dsm *, u32 *);

int dsm_zero_pfn_init(void);
void dsm_zero_pfn_exit(void);
#endif /* DSM_CORE_H_ */
