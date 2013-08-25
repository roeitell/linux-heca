/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */
#include <linux/hash.h>
#include <linux/hugetlb.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/writeback.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_context.h>
#include <asm-generic/cacheflush.h>
#include "../../../mm/internal.h"

#include "ioctl.h"
#include "trace.h"
#include "struct.h"
#include "push.h"
#include "base.h"
#include "pull.h"
#include "ops.h"

static unsigned long congestion = 0;
inline int heca_is_congested(void)
{
        if (HECA_CONGESTION_THRESHOLD) {
                trace_heca_is_congested(congestion);
                return congestion > HECA_CONGESTION_THRESHOLD;
        } else {
                return 0;
        }
}

static inline void heca_push_finish_notify(struct page *page)
{
        struct zone *zone = page_zone(page);
        wait_queue_head_t *waitqueue =
                &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
        rotate_reclaimable_page(page);
        ClearPageDirty(page);
        TestClearPageWriteback(page);
        __wake_up_bit(waitqueue, &page->flags, PG_writeback);
}

static int heca_push_cache_add(struct heca_page_cache *hpc,
                struct heca_process *hproc, unsigned long addr)
{
        struct heca_page_cache *rb_hpc;
        struct rb_node **new, *parent = NULL;
        int r = 0;

        write_seqlock(&hproc->push_cache_lock);
        for (new = &hproc->push_cache.rb_node; *new;) {
                rb_hpc = rb_entry(*new, struct heca_page_cache, rb_node);
                parent = *new;
                BUG_ON(!rb_hpc);
                if (addr < rb_hpc->addr)
                        new = &(*new)->rb_left;
                else if (addr > rb_hpc->addr)
                        new = &(*new)->rb_right;
                else {
                        r = -EEXIST;
                        goto out;
                }
        }

        rb_link_node(&hpc->rb_node, parent, new);
        rb_insert_color(&hpc->rb_node, &hproc->push_cache);

out:
        write_sequnlock(&hproc->push_cache_lock);
        return r;
}

static struct heca_page_cache *heca_push_cache_get(struct heca_process *hproc,
                unsigned long addr, struct heca_process *remote_hproc)
{
        struct rb_node *node;
        struct heca_page_cache *hpc = NULL;
        int seq, i;

        BUG_ON(!hproc);

        do {
                seq = read_seqbegin(&hproc->push_cache_lock);
                for (node = hproc->push_cache.rb_node; node; hpc = NULL) {
                        hpc = rb_entry(node, struct heca_page_cache, rb_node);
                        BUG_ON(!hpc);
                        if (addr < hpc->addr)
                                node = node->rb_left;
                        else if (addr > hpc->addr)
                                node = node->rb_right;
                        else
                                break;
                }
        } while (read_seqretry(&hproc->push_cache_lock, seq));

        if (likely(hpc) && remote_hproc) {
                for (i = 0; i < hpc->hprocs.num; i++) {
                        if (hpc->hprocs.ids[i] == remote_hproc->hproc_id) {
                                if (likely(test_and_clear_bit(i, &hpc->bitmap)
                                                        && atomic_add_unless(&hpc->nproc, 1, 0))) {
                                        goto out;
                                }
                                break;
                        }
                }
                hpc = NULL;
        }

out:
        return hpc;
}

inline void heca_push_cache_release(struct heca_process *hproc,
                struct heca_page_cache **hpc, int lock)
{
        if (likely(lock)) {
                write_seqlock(&hproc->push_cache_lock);
                rb_erase(&(*hpc)->rb_node, &hproc->push_cache);
                write_sequnlock(&hproc->push_cache_lock);
        } else {
                /* !lock only when traversing push_cache when removing hprocs */
                rb_erase(&(*hpc)->rb_node, &hproc->push_cache);
        }
        if (likely((*hpc)->pages[0])) {
                page_cache_release((*hpc)->pages[0]);
                heca_push_finish_notify((*hpc)->pages[0]);
        }
        heca_dealloc_hpc(hpc);
        congestion--;
}

/* mmap_sem already held for read */
static int heca_initiate_fault_fast(struct mm_struct *mm, unsigned long addr,
                int usemm)
{
        int r;

        might_sleep();

        if (usemm) {
                use_mm(mm);
                r = get_user_pages(current, mm, addr, 1, 1, 0, NULL, NULL);
                unuse_mm(mm);
        } else {
                r = get_user_pages(current, mm, addr, 1, 1, 0, NULL, NULL);
        }

        BUG_ON(r > 1);
        return r == 1;
}

int heca_extract_pte_data(struct heca_pte_data *pd, struct mm_struct *mm,
                unsigned long addr)
{
        pmd_t pmdval;
        pd->pte = NULL;
        pd->vma = find_vma(mm, addr);
        if (unlikely(!pd->vma || pd->vma->vm_start > addr))
                return -1;

        pd->pgd = pgd_offset(mm, addr);
        if (unlikely(!pgd_present(*(pd->pgd))))
                return -2;

        pd->pud = pud_offset(pd->pgd, addr);
        if (unlikely(!pud_present(*(pd->pud))))
                return -3;

        pd->pmd = pmd_offset(pd->pud, addr);
        pmdval = pmd_read_atomic(pd->pmd);
        /*
         *  we do not need the barrier here as we target 64bit arch only
         *  barrier is only necessary on 32 bit arch as the pmd require 2 read
         *  access
         */
        if (unlikely(pmd_none(pmdval))) {
                return -4;
        }
        if (unlikely(pmd_bad(pmdval))) {
                if(!pmd_trans_huge(pmdval)){
                        pmd_clear_bad(pd->pmd);
                        return -5;
                }else{
                        spin_lock(&mm->page_table_lock);
                        if (likely(pmd_trans_huge(*(pd->pmd)))) {
                                if (unlikely(pmd_trans_splitting(*(pd->pmd)))) {
                                        spin_unlock(&mm->page_table_lock);
                                        wait_split_huge_page(pd->vma->anon_vma,
                                                        pd->pmd);
                                } else {
                                        spin_unlock(&mm->page_table_lock);
                                        split_huge_page_pmd(pd->vma, addr,
                                                        pd->pmd);
                                }
                        } else {
                                spin_unlock(&mm->page_table_lock);
                        }
                }
        }
        pd->pte = pte_offset_map(pd->pmd, addr);
        return !pd->pte;
}

static inline u32 heca_pte_maintainer(swp_entry_t swp_e)
{
        struct heca_swp_data hsd;
        u32 hproc_id = 0;

        if (!is_heca_entry(swp_e))
                goto out;

        /* heca is missing, we can bail out */
        if (swp_entry_to_heca_data(swp_e, &hsd) < 0)
                goto out;

        /*
         * we currently only support RRAIM for a specific configuration, consisting
         * of a single active node, and other passive nodes supplying memory.
         */
        BUG_ON(hsd.hprocs.num > 1);

        /* FIXME: a deadlock waiting to happen; what can we do? */
        if (unlikely(!hsd.hprocs.ids[0]))
                goto out;

        hproc_id = hsd.hprocs.ids[0];
out:
        return hproc_id;
}

/* if we don't find a hspace pte, we assume the page is ours */
u32 heca_query_pte_info(struct heca_process *hproc, unsigned long addr)
{
        struct heca_pte_data pd;
        pte_t *pte;
        spinlock_t *ptl = NULL;
        swp_entry_t swp_e;
        u32 hproc_id = hproc->hproc_id, pte_hproc_id;
        struct mm_struct *mm = hproc->mm;

        BUG_ON(!mm);
        down_read(&mm->mmap_sem);
retry:
        if (unlikely(heca_extract_pte_data(&pd, mm, addr)))
                goto out;

        pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*(pd.pte), *pte))) {
                spin_unlock(ptl);
                goto retry;
        }

        if (pte_none(*pte) || pte_present(*pte))
                goto out;

        swp_e = pte_to_swp_entry(*pte);
        if (unlikely(!non_swap_entry(swp_e)))
                goto out;

        if (unlikely(is_migration_entry(swp_e))) {
                migration_entry_wait(mm, pd.pmd, addr);
                goto retry;
        }

        pte_hproc_id = heca_pte_maintainer(swp_e);
        if (likely(pte_hproc_id))
                hproc_id = pte_hproc_id;

out:
        if (ptl)
                spin_unlock(ptl);
        up_read(&mm->mmap_sem);
        return hproc_id;
}

static int heca_extract_read_hspace_pte(struct heca_process *local_hproc,
                struct mm_struct *mm, unsigned long addr, pte_t pte_entry,
                struct heca_pte_data *pd, int *redirect_id)
{
        swp_entry_t swp_e;
        struct heca_page_cache *hpc = NULL;

        /* page could be swapped to disk */
        swp_e = pte_to_swp_entry(pte_entry);
        if (!non_swap_entry(swp_e))
                goto fail;

        if (is_migration_entry(swp_e)) {
                migration_entry_wait(mm, pd->pmd, addr);
                goto fail;
        }

        /* we check if we are already pulling */
        hpc = heca_cache_get(local_hproc, addr);
        if (hpc)
                goto fail;

        *redirect_id = heca_pte_maintainer(swp_e);
        if (unlikely(!(*redirect_id)))
                goto fail;

        return 0;

        /* couldn't find a redirect, gup needed */
fail:
        return -EFAULT;
}

int heca_pte_present(struct mm_struct *mm, unsigned long addr)
{
        struct heca_pte_data pd;
        int r;

        /*
         * we don't have to be 100% accurate here, just make sure the page table
         * isn't freed while we're inspecting it (see gup.c).
         */
        local_irq_disable();
        r = heca_extract_pte_data(&pd, mm, addr);
        local_irq_enable();

        if (unlikely(r)) {
                trace_heca_extract_pte_data_err(r);
                return 0;
        }

        return pte_present(*(pd.pte));
}

/* returns # of pages unmapped (0 or 1) or -EFAULT on failure */
int heca_try_unmap_page(struct heca_process *local_hproc, unsigned long addr,
                struct heca_process *remote_hproc, int only_unmap)
{
        struct heca_pte_data pd;
        struct page *page;
        spinlock_t *ptl;
        pte_t pte_entry;
        int r, touch_page = 1;
        struct mm_struct *mm = local_hproc->mm;

        down_read(&mm->mmap_sem);

retry:
        r = heca_extract_pte_data(&pd, mm, addr);
        if (unlikely(r)) {
                trace_heca_extract_pte_data_err(r);
                goto out_mm;
        }

        pte_entry = *(pd.pte);
        pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);

        /* FIXME: is this clause necessary at all? */
        if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
                pte_unmap_unlock(pd.pte, ptl);
                goto retry;
        }

        /*
         * this could signal one of two things: either we don't fully possess the
         * page yet (in which case we can't answer), or we are the maintainers, and
         * trying to invalidate read-copies (in which case we can't answer). no need
         * to differentiate between these two, just don't answer.
         */
        if (unlikely(heca_cache_get(local_hproc, addr))) {
                r = -EEXIST;
                goto out;
        }

        /* first access to page */
        if (pte_none(pte_entry)) {
                set_pte_at(mm, addr, pd.pte,
                                heca_descriptor_to_pte(
                                        remote_hproc->descriptor, 0));
                goto out;
        }

        /* page already unmapped somewhere, update the entry */
        if (!pte_present(pte_entry)) {
                if (!only_unmap) {
                        pte_t new_pte = heca_descriptor_to_pte(
                                        remote_hproc->descriptor, 0);
                        if (!pte_same(pte_entry, new_pte)) {
                                if (unlikely(!is_heca_entry(pte_to_swp_entry(pte_entry)))) {
                                        pte_unmap_unlock(pd.pte, ptl);
                                        heca_initiate_fault_fast(mm, addr, 1);
                                        goto retry;
                                }

                                touch_page = 0;
                                goto unmap;
                        }
                }
                /* TODO: If pte isn't heca, gup or defer_gup (it should be heca); If pte
                 * is heca, validate descriptor == remote_hspace->descriptor
                 */
                r = -EEXIST;
                goto out;
        }

        /* we invalidated the requester's copy while it was waiting for us */
        if (unlikely(pte_write(pte_entry))) {
                r = -EEXIST;
                goto out;
        }

        page = vm_normal_page(pd.vma, addr, pte_entry);
        if (!page) {
                /* HECA3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf */
                if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
                        goto out;

                page = pte_page(*(pd.pte));
        }

        if (unlikely(PageTransHuge(page))) {
                if (!PageHuge(page) && PageAnon(page)) {
                        pte_unmap_unlock(pd.pte, ptl);
                        if (unlikely(split_huge_page(page)))
                                goto out;
                        goto retry;
                }
        }

        if (unlikely(PageKsm(page))) {
                pte_unmap_unlock(pd.pte, ptl);
                if (!heca_initiate_fault(mm, addr, 1)) {
                        r = -EFAULT;  /* HECA1 : better ksm error handling required. */
                        goto out;
                }
        }

unmap:
        flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
        ptep_clear_flush(pd.vma, addr, pd.pte);
        set_pte_at(mm, addr, pd.pte,
                        heca_descriptor_to_pte(remote_hproc->descriptor, 0));

        if (touch_page) {
                page_remove_rmap(page);
                dec_mm_counter(mm, MM_ANONPAGES);
                touch_page = 2; /* page touched, released after unlock */
        }

out:
        pte_unmap_unlock(pd.pte, ptl);
        if (touch_page == 2) {
                mmu_notifier_invalidate_page(mm, addr);
                page_cache_release(page);
        }
out_mm:
        up_read(&mm->mmap_sem);

        if (likely(!r))
                return touch_page == 2;
        return -EFAULT;
}

/* we arrive with mm semaphore held */
static int heca_extract_page(struct heca_process *local_hproc,
                struct heca_process *remote_hproc,
                struct mm_struct *mm, unsigned long addr,
                pte_t *return_pte, u32 *hproc_id, int deferred,
                struct page **page, struct heca_memory_region *mr, int read_copy)
{
        spinlock_t *ptl;
        int r, res = HECA_EXTRACT_FAIL;
        struct heca_pte_data pd;
        pte_t pte_entry;
        u32 maintainer_id;

retry:
        r = 0;
        *page = NULL;
        r = heca_extract_pte_data(&pd, mm, addr);
        if (unlikely(r)) {
                trace_heca_extract_pte_data_err(r);
                if (likely(deferred && r != -1)) {
                        if (heca_initiate_fault_fast(mm, addr, 1))
                                goto retry;
                }
                goto out;
        }
        pte_entry = *(pd.pte);

        /* first time dealing with this addr? */
        if (pte_none(pte_entry)) {
                if (!heca_initiate_fault_fast(mm, addr, 1))
                        goto out;
                goto retry;
        }

        pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
                pte_unmap_unlock(pd.pte, ptl);
                goto retry;
        }

        if (unlikely(!pte_present(pte_entry))) {
                /* try and redirect, according to a heca pte */
                if (!heca_extract_read_hspace_pte(local_hproc, mm, addr, pte_entry,
                                        &pd, hproc_id)) {
                        res = HECA_EXTRACT_REDIRECT;

                /* it's time to fault the page in... */
                } else if (deferred) {
                        pte_unmap_unlock(pd.pte, ptl);
                        if (!heca_initiate_fault_fast(mm, addr, 1))
                                goto out;
                        goto retry;
                }
                goto no_page;
        }

        /* we only have a read-copy, so we redirect to the maintainer */
        maintainer_id = heca_lookup_page_read(local_hproc, addr);
        if (unlikely(maintainer_id)) {
                *hproc_id = maintainer_id;
                res = HECA_EXTRACT_REDIRECT;
                goto no_page;
        }

        *page = vm_normal_page(pd.vma, addr, *(pd.pte));
        if (!(*page)) {
                /* HECA3 : follow_page uses - goto no_page; when !ZERO_PAGE..? wtf */
                if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
                        goto no_page;

                *page = pte_page(*(pd.pte));
        }

        if (unlikely(PageTransHuge(*page))) {
                if (!PageHuge(*page) && PageAnon(*page)) {
                        pte_unmap_unlock(pd.pte, ptl);
                        if (unlikely(split_huge_page(*page)))
                                goto no_page;
                        goto retry;
                }
        }

        if (unlikely(PageKsm(*page))) {
                pte_unmap_unlock(pd.pte, ptl);
                if (!heca_initiate_fault_fast(mm, addr, 1))
                        goto out;
                goto retry;
        }


        page_cache_get(*page);

        if (!(mr->flags & MR_COPY_ON_ACCESS)) {
                /* FIXME: Should we not lock the page here?! */
                flush_cache_page(pd.vma, addr, pte_pfn(pte_entry));
                ptep_clear_flush(pd.vma, addr, pd.pte);
                if (read_copy) {
                        pte_entry = pte_mkclean(pte_wrprotect(pte_entry));
                        heca_add_reader(local_hproc, addr, remote_hproc->hproc_id);
                } else {
                        pte_entry = heca_descriptor_to_pte(remote_hproc->descriptor,
                        		HECA_INFLIGHT);
                        page_remove_rmap(*page);
                        dec_mm_counter(mm, MM_ANONPAGES);
                        /* FIXME: the following line might_sleep, as it sends msgs */
                        heca_invalidate_readers(local_hproc,
                                        addr, remote_hproc->hproc_id);
                }
                set_pte_at(mm, addr, pd.pte, pte_entry);
        }

        *return_pte = *(pd.pte);

        pte_unmap_unlock(pd.pte, ptl);
        if (!(mr->flags & MR_COPY_ON_ACCESS) && !read_copy) {
                mmu_notifier_invalidate_page(mm, addr);
                page_cache_release(*page);
        }
        return HECA_EXTRACT_SUCCESS;

no_page:
        pte_unmap_unlock(pd.pte, ptl);
out:
        return res;
}

void heca_invalidate_readers(struct heca_process *hproc, unsigned long addr,
                u32 exclude_id)
{
        /*
         * holding the spinlock while notifying the readers will not be helpful,
         * since after we will release it, the page could still be transferred
         * anywhere, and any read-copies could be re-created...
         */
        struct heca_page_reader *hpr = heca_delete_readers(hproc, addr);

        while (hpr) {
                struct heca_page_reader *tmp = hpr;
                struct heca_process *remote_hproc;
                struct heca_memory_region *mr;

                if (hpr->hproc_id != exclude_id) {
                        remote_hproc = find_hproc(hproc->hspace, hpr->hproc_id);
                        if (likely(remote_hproc)) {
                                mr = search_heca_mr_by_addr(hproc, addr);
                                if (likely(mr))
                                        heca_claim_page(hproc, remote_hproc, mr,
                                                        addr, NULL, 0);
                                release_hproc(remote_hproc);
                        }
                }

                hpr = hpr->next;
                heca_free_page_reader(tmp);
        }
}

int heca_lookup_page_in_remote(struct heca_process *local_hproc,
                struct heca_process *remote_hproc, unsigned long addr,
                struct page **page)
{
        struct heca_page_cache *hpc;

        hpc = heca_push_cache_get(local_hproc, addr, remote_hproc);
        if (unlikely(!hpc))
                goto fail;

        *page = hpc->pages[0];
        atomic_dec(&hpc->nproc);
        if (find_first_bit(&hpc->bitmap, hpc->hprocs.num) >= hpc->hprocs.num &&
                        atomic_cmpxchg(&hpc->nproc, 1, 0) == 1) {
                heca_push_cache_release(local_hproc, &hpc, 1);
        }

        return HECA_EXTRACT_SUCCESS;

fail:
        return HECA_EXTRACT_FAIL;
}

int heca_extract_page_from_remote(struct heca_process *local_hproc,
                struct heca_process *remote_hproc,
                unsigned long addr, u16 tag,
                pte_t *pte, struct page **page, u32 *hproc_id, int deferred,
                struct heca_memory_region *mr)
{
        int res;

        down_read(&local_hproc->mm->mmap_sem);
        res = heca_extract_page(local_hproc, remote_hproc, local_hproc->mm,
                        addr, pte, hproc_id, deferred, page, mr,
                        tag == MSG_REQ_READ);
        up_read(&local_hproc->mm->mmap_sem);

        return res;
}

/* this function is purely for development, used in the PUSH ioctl */
struct page *heca_find_normal_page(struct mm_struct *mm, unsigned long addr)
{
        struct page *page = NULL;
        struct heca_pte_data pd;
        pte_t pte_entry, *pte;
        spinlock_t *ptl;

        if (heca_extract_pte_data(&pd, mm, addr))
                goto out;

        pte_entry = *(pd.pte);
        if (!pte_present(pte_entry))
                goto out;

retry:
        pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (!pte_same(*pte, pte_entry)) {
                pte_unmap_unlock(pte, ptl);
                goto retry;
        }
        page = vm_normal_page(pd.vma, addr, *pte);
        pte_unmap_unlock(pte, ptl);

out:
        return page;
}

int heca_prepare_page_for_push(struct heca_process *local_hproc,
                struct heca_process_list hprocs, struct page *page, unsigned long addr,
                struct mm_struct *mm, u32 descriptor)
{
        struct heca_pte_data pd;
        struct heca_page_cache *hpc = NULL;
        pte_t pte_entry, *pte;
        spinlock_t *ptl;
        int i, r;

        hpc = heca_alloc_hpc(local_hproc, addr, hprocs, 1, descriptor);
        if (unlikely(!hpc))
                return -ENOMEM;

retry:
        /* we're trying to swap out an active page, everything should be here */
        /* we lock the pte to avoid racing with an incoming page request */
        heca_extract_pte_data(&pd, mm, addr);
        BUG_ON(!pd.pte);
        pte_entry = *(pd.pte);
        if (unlikely(!pte_present(pte_entry)))
                goto bad_page;

        pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*pte, pte_entry))) {
                pte_unmap_unlock(pte, ptl);
                goto retry;
        }

        if (unlikely(PageTransHuge(page) && !PageHuge(page) &&
                                PageAnon(page))) {
                if (unlikely(split_huge_page(page)))
                        goto bad_page_unlock;
        }

        if (unlikely(PageKsm(page))) {
                pte_unmap_unlock(pd.pte, ptl);
                if (!heca_initiate_fault(mm, addr, 1))
                        goto bad_page;
                goto retry;
        }

        r = heca_push_cache_add(hpc, local_hproc, addr);
        if (unlikely(r))
                goto bad_page_unlock;

        hpc->bitmap = 0;
        hpc->pages[0] = page;

        /*
         * refcount is as follows:
         *  1 for being in dpc (released upon dealloc)
         *  1 for every hproc sent to (released on heca_ppe_clear_release)
         */
        page_cache_get(page);
        for_each_valid_hproc(hprocs, i) {
                page_cache_get(page);
                hpc->bitmap += (1 << i);
        }

        /*
         * PageWriteback signals shrink_page_list it can either synchronously wait
         * for op to complete, or just ignore the page and continue. It also gives
         * __isolate_lru_page a chance to bail.
         */
        SetPageDirty(page);
        TestSetPageWriteback(page);

        /* unmap the page */
        flush_cache_page(pd.vma, addr, pte_pfn(pte_entry));
        ptep_clear_flush(pd.vma, addr, pd.pte);
        set_pte_at(mm, addr, pd.pte, heca_descriptor_to_pte(hpc->tag, 0));
        page_remove_rmap(page);
        dec_mm_counter(mm, MM_ANONPAGES);

        pte_unmap_unlock(pte, ptl);
        mmu_notifier_invalidate_page(mm, addr);
        page_cache_release(page);
        congestion++;

        /* may happen outside the lock, but before we return */
        heca_invalidate_readers(local_hproc, addr, 0);

        return 0;

bad_page_unlock:
        pte_unmap_unlock(pte, ptl);
bad_page:
        heca_dealloc_hpc(&hpc);
        return -EFAULT;
}

/* we arrive from shrink_page_list with page already locked */
static int heca_try_discard_read_copy(struct heca_process *hproc,
                unsigned long addr, struct page *page,
                struct vm_area_struct *vma,
                struct heca_memory_region *mr)
{
        struct heca_pte_data pd;
        pte_t *ptep;
        spinlock_t *ptl;
        int ret = 0, release = 0;
        struct mm_struct *mm = vma->vm_mm;
        u32 maintainer_id, descriptor;
        struct heca_process *maintainer;

retry:
        if (!heca_lookup_page_read(hproc, addr))
                return -EEXIST;

        heca_extract_pte_data(&pd, mm, addr);

        ptep = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);

        maintainer_id = heca_extract_page_read(hproc, addr);
        if (unlikely(!maintainer_id)) {
                ret = -EEXIST;
                goto unlock;
        }

        if (unlikely(!pte_present(*ptep))) {
                ret = -EINVAL;
                goto unlock;
        }

        if (unlikely(PageTransHuge(page) && !PageHuge(page) &&
                                PageAnon(page))) {
                if (unlikely(split_huge_page(page))) {
                        ret = -EFAULT;
                        goto unlock;
                }
        }

        if (unlikely(PageKsm(page))) {
                pte_unmap_unlock(ptep, ptl);
                if (!heca_initiate_fault(mm, addr, 1))
                        return -EFAULT;
                goto retry;
        }

        /* lockless, much faster than heca_get_descriptor */
        maintainer = find_hproc(hproc->hspace, maintainer_id);
        if (likely(maintainer)) {
                descriptor = maintainer->descriptor;
                release_hproc(maintainer);
        } else {
                descriptor = mr->descriptor;
        }

        flush_cache_page(pd.vma, addr, pte_pfn(*ptep));
        ptep_clear_flush(pd.vma, addr, pd.pte);
        release = 1;
        set_pte_at(mm, addr, ptep, heca_descriptor_to_pte(descriptor, 0));
        page_remove_rmap(page);
        dec_mm_counter(mm, MM_ANONPAGES);
        if (unlikely(PageSwapCache(page)))
                try_to_free_swap(page);
        unlock_page(page);
        trace_heca_discard_read_copy(hproc->hspace->hspace_id, hproc->hproc_id,
                        maintainer_id, mr->hmr_id, addr, addr-mr->addr, 0);
unlock:
        pte_unmap_unlock(ptep, ptl);
        if (release) {
                mmu_notifier_invalidate_page(mm, addr);
                page_cache_release(page);
        }
        return ret;
}

int heca_cancel_page_push(struct heca_process *hproc, unsigned long addr,
                struct page *page)
{
        struct heca_page_cache *hpc = heca_push_cache_get(hproc, addr, NULL);
        int i;

        if (unlikely(!hpc))
                return -1;

        /* hproc_list could have changed in the meanwhile, we rely on bitmap */
        for (i = 0; i < hpc->hprocs.num; i++) {
                if (test_bit(i, &hpc->bitmap))
                        page_cache_release(hpc->pages[0]);
        }
        heca_push_cache_release(hproc, &hpc, 1);

        return 0;
}

/*
 * Return 0 => page heca or not heca_remote => try to swap out
 * Return 1 => page is heca => do not swap out (not necessarily scheduled yet to
 *             be pushed back, could also be done in next cycle)
 */
int push_back_if_remote_heca_page(struct page *page)
{
        struct anon_vma *anon_vma;
        pgoff_t pgoff;
        struct anon_vma_chain *avc;
        int ret = 0;

        if (!get_heca_module_state())
                goto out;

        /* don't push pages that belong to more than one process, avoid pitfalls */
        if (page_mapcount(page) > 1)
                goto out;

        anon_vma = page_lock_anon_vma_read(page);
        if (!anon_vma)
                goto out;

        /* note: should actually find only one relevant vma */
        pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
        anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff)
        {
                struct vm_area_struct *vma = avc->vma;
                unsigned long address;
                struct heca_process *hproc;
                struct heca_memory_region *mr;
                int discarded = 0;

                address = page_address_in_vma(page, vma);
                if (address == -EFAULT)
                        continue;

                hproc = find_local_hproc_from_mm(vma->vm_mm);
                if (!hproc)
                        continue;

                /* lookup a remote mr owner, to push the page to */
                mr = search_heca_mr_by_addr(hproc, address);
                if (!mr || mr->flags & (MR_LOCAL | MR_COPY_ON_ACCESS)) {
                        release_hproc(hproc);
                        continue;
                }
                /* we need to unlock the VMA before doing and Heca operation
                 * (split_huge_page and other try to try to grab the vma lock) */
                page_unlock_anon_vma_read(anon_vma);
                /* if we have a read-copy, try to discard it without any networking */
                discarded = heca_try_discard_read_copy(hproc, address,
                                page, vma, mr);
                if (discarded < 0) {
                        if (discarded == -EEXIST) {
                                heca_request_page_pull(hproc->hspace, hproc, page,
                                                address, vma->vm_mm, mr);
                        }
                        if (unlikely(PageSwapCache(page)))
                                try_to_free_swap(page);
                        unlock_page(page);
                }

                release_hproc(hproc);
                ret = 1;
                goto out;
        }

        page_unlock_anon_vma_read(anon_vma);
out:
        return ret;
}

/* no locks are held when calling this function */
int hproc_flag_page_remote(struct mm_struct *mm, struct heca_space *hspace, u32 descriptor,
                unsigned long request_addr)
{
        spinlock_t *ptl;
        pte_t *pte;
        int r = 0, release = 0;
        struct page *page = 0;
        struct vm_area_struct *vma;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pmd_t pmdval;
        pte_t pte_entry;
        swp_entry_t swp_e;
        unsigned long addr = request_addr & PAGE_MASK;

        down_read(&mm->mmap_sem);

retry:
        r = 0;
        vma = find_vma(mm, addr);
        if (unlikely(!vma || vma->vm_start > addr)) {
                heca_printk(KERN_ERR "no vma");
                goto out;
        }

        // ksm_flag = vma->vm_flags & VM_MERGEABLE;

        pgd = pgd_offset(mm, addr);
        if (unlikely(!pgd_present(*pgd))) {
                if (!heca_initiate_fault_fast(mm, addr, 0)){
                        heca_printk(KERN_ERR "no pgd");
                        r = -EFAULT;
                        goto out;
                }
                goto retry;
        }

        pud = pud_offset(pgd, addr);
        if (unlikely(!pud_present(*pud))) {
                if (!heca_initiate_fault_fast(mm, addr, 0)) {
                        heca_printk(KERN_ERR "no pud");
                        r = -EFAULT;
                        goto out;
                }
                goto retry;
        }

        pmd = pmd_offset(pud, addr);
        pmdval = pmd_read_atomic(pmd);
        if (unlikely(pmd_none(pmdval))) {
                __pte_alloc(mm, vma, pmd, addr);
                goto retry;
        }
        if (unlikely(pmd_bad(pmdval))) {
                if(!pmd_trans_huge(pmdval)){
                        pmd_clear_bad(pmd);
                        heca_printk(KERN_ERR "bad pmd");
                        goto out;
                }else{
                        spin_lock(&mm->page_table_lock);
                        if (likely(pmd_trans_huge(*pmd))) {
                                if (unlikely(pmd_trans_splitting(*pmd))) {
                                        spin_unlock(&mm->page_table_lock);
                                        wait_split_huge_page(vma->anon_vma, pmd);
                                } else {
                                        spin_unlock(&mm->page_table_lock);
                                        split_huge_page_pmd(vma, addr, pmd);
                                }
                        } else {
                                spin_unlock(&mm->page_table_lock);
                                split_huge_page_pmd(vma, addr, pmd);
                        }
                }
        }
        // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock
        pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
                if (pte_none(pte_entry)) {
                        set_pte_at(mm, addr, pte,
                                        heca_descriptor_to_pte(descriptor, 0));
                        goto out_pte_unlock;
                } else {
                        swp_e = pte_to_swp_entry(pte_entry);
                        if (non_swap_entry(swp_e)) {
                                if (is_migration_entry(swp_e)) {
                                        pte_unmap_unlock(pte, ptl);
                                        migration_entry_wait(mm, pmd, addr);
                                        goto retry;
                                } else {
                                        r = -EFAULT;
                                        goto out_pte_unlock;
                                }
                        } else {
                                pte_unmap_unlock(pte, ptl);
                                if (!heca_initiate_fault_fast(mm, addr, 0)) {
                                        heca_printk(KERN_ERR "failed at faulting");
                                        r = -EFAULT;
                                        goto out;
                                }
                                r = 0;
                                goto retry;
                        }
                }
        } else {
                page = vm_normal_page(vma, request_addr, *pte);
                if (unlikely(!page)) {
                        //HECA1 we need to test if the pte is not null
                        page = pte_page(*pte);
                }
        }
        if (PageTransHuge(page)) {
                heca_printk(KERN_ERR "we have a huge page");
                if (!PageHuge(page) && PageAnon(page)) {
                        if (unlikely(split_huge_page(page))) {
                                heca_printk(KERN_ERR "failed at splitting page");
                                goto out;
                        }
                }
        }
        if (PageKsm(page)) {
                heca_printk(KERN_ERR "KSM page");
                pte_unmap_unlock(pte, ptl);
                if (!heca_initiate_fault_fast(mm, addr, 0)) {
                        heca_printk(KERN_ERR "ksm_madvise ret : %d", r);
                        // HECA1 : better ksm error handling required.
                        r = -EFAULT;
                        goto out;
                }
                goto retry;
        }

        if (!trylock_page(page)) {
                heca_printk(KERN_ERR "couldn't lock page");
                r = -EFAULT;
                goto out_pte_unlock;
        }

        flush_cache_page(vma, addr, pte_pfn(*pte));
        ptep_clear_flush(vma, addr, pte);
        set_pte_at(mm, addr, pte, heca_descriptor_to_pte(descriptor, 0));
        page_remove_rmap(page);

        dec_mm_counter(mm, MM_ANONPAGES);

        // this is a page flagging without data exchange so we can free the page

        unlock_page(page);
        release = 1;

out_pte_unlock:
        pte_unmap_unlock(pte, ptl);
        if (release) {
                mmu_notifier_invalidate_page(mm, addr);
                page_cache_release(page);
        }
out:
        up_read(&mm->mmap_sem);
        return r;
}

