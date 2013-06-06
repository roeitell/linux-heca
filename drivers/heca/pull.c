/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

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
#include "pull.h"
#include "push.h"
#include "base.h"
#include "ops.h"
#include "conn.h"
#include "base.h"

static struct kmem_cache *dsm_delayed_fault_cache_kmem;
unsigned long zero_dsm_pfn __read_mostly;

void init_dsm_prefetch_cache_kmem(void)
{
    dsm_delayed_fault_cache_kmem = kmem_cache_create("dsm_delayed_fault_cache",
            sizeof(struct dsm_delayed_fault), 0,
            SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY, NULL);
}

void destroy_dsm_prefetch_cache_kmem(void)
{
    kmem_cache_destroy(dsm_delayed_fault_cache_kmem);
}

static struct dsm_delayed_fault *alloc_dsm_delayed_fault_cache_elm(
        unsigned long addr)
{
    struct dsm_delayed_fault *ddf = kmem_cache_alloc(
            dsm_delayed_fault_cache_kmem, GFP_KERNEL);
    if (unlikely(!ddf))
        goto out;

    ddf->addr = addr;

out:
    return ddf;
}

static void free_dsm_delayed_fault_cache_elm(struct dsm_delayed_fault ** ddf)
{
    kmem_cache_free(dsm_delayed_fault_cache_kmem, *ddf);
    *ddf = NULL;
}

int dsm_zero_pfn_init(void)
{
    zero_dsm_pfn = page_to_pfn(ZERO_PAGE(0));
    return 0;
}

void dsm_zero_pfn_exit(void)
{
    zero_dsm_pfn = 0;
}

static inline int is_dsm_zero_pfn(unsigned long pfn)
{
    return pfn == zero_dsm_pfn;
}

static int reuse_dsm_page(struct page *page, unsigned long addr,
        struct dsm_page_cache *dpc)
{
    int count;

    VM_BUG_ON(!PageLocked(page));
    if (unlikely(PageKsm(page)))
        return 0;

    count = page_mapcount(page);
    if (count == 0 && !PageWriteback(page)) {
        dpc->released = 1;
        if (!PageSwapBacked(page))
            SetPageDirty(page);
    }

    return count <= 1;
}

static inline void cow_user_page(struct page *dst, struct page *src,
        unsigned long va, struct vm_area_struct *vma)
{
    if (unlikely(!src)) {
        void *kaddr = kmap_atomic(dst);
        void __user *uaddr = (void __user *) (va & PAGE_MASK);

        if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE))
            clear_page(kaddr);
        kunmap_atomic(kaddr);
        flush_dcache_page(dst);
    } else
        copy_user_highpage(dst, src, va, vma);
}

static int do_wp_dsm_page(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl,
        pte_t orig_pte, unsigned long norm_address, struct dsm_page_cache *dpc)
        __releases(ptl)
{
    struct page *old_page, *new_page;
    pte_t entry;
    int ret = 0;
    int page_mkwrite = 0;
    struct page *dirty_page = NULL;
    unsigned long mmun_start = 0, mmun_end = 0;

    old_page = vm_normal_page(vma, address, orig_pte);
    if (!old_page) {
        if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == (VM_WRITE | VM_SHARED))
            goto reuse;
        goto gotten;
    }

    if (PageAnon(old_page) && !PageKsm(old_page)) {
        if (!trylock_page(old_page)) {
            page_cache_get(old_page);
            pte_unmap_unlock(page_table, ptl);
            lock_page(old_page);
            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (!pte_same(*page_table, orig_pte)) {
                unlock_page(old_page);
                goto unlock;
            }
            page_cache_release(old_page);
        }
        if (reuse_dsm_page(old_page, norm_address, dpc)) {
            page_move_anon_rmap(old_page, vma, address);
            unlock_page(old_page);
            goto reuse;
        }
        unlock_page(old_page);
    } else if (unlikely(
            (vma->vm_flags & (VM_WRITE | VM_SHARED)) == (VM_WRITE | VM_SHARED))) {

        if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
            struct vm_fault vmf;
            int tmp;

            vmf.virtual_address = (void __user *) (address & PAGE_MASK);
            vmf.pgoff = old_page->index;
            vmf.flags = FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE;
            vmf.page = old_page;

            page_cache_get(old_page);
            pte_unmap_unlock(page_table, ptl);

            tmp = vma->vm_ops->page_mkwrite(vma, &vmf);
            if (unlikely(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
                ret = tmp;
                goto unwritable_page;
            }
            if (unlikely(!(tmp & VM_FAULT_LOCKED))) {
                lock_page(old_page);
                if (!old_page->mapping) {
                    ret = 0; /* retry the fault */
                    unlock_page(old_page);
                    goto unwritable_page;
                }
            } else
                VM_BUG_ON(!PageLocked(old_page));

            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (!pte_same(*page_table, orig_pte)) {
                unlock_page(old_page);
                goto unlock;
            }

            page_mkwrite = 1;
        }
        dirty_page = old_page;
        page_cache_get(dirty_page);

reuse:
        flush_cache_page(vma, address, pte_pfn(orig_pte));
        entry = pte_mkyoung(orig_pte);
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);
        if (ptep_set_access_flags(vma, address, page_table, entry, 1))
            update_mmu_cache(vma, address, page_table);


        pte_unmap_unlock(page_table, ptl);
        ret |= VM_FAULT_WRITE;

        if (!dirty_page)
            return ret;

        if (!page_mkwrite) {
            wait_on_page_locked(dirty_page);
            set_page_dirty_balance(dirty_page, page_mkwrite);
            if (vma->vm_file)
                file_update_time(vma->vm_file);
        }
        put_page(dirty_page);
        if (page_mkwrite) {
            struct address_space *mapping = dirty_page->mapping;

            set_page_dirty(dirty_page);
            unlock_page(dirty_page);
            page_cache_release(dirty_page);
            if (mapping) {
                balance_dirty_pages_ratelimited(mapping);
            }
        }

        return ret;
    }

    page_cache_get(old_page);
gotten:
    pte_unmap_unlock(page_table, ptl);

    if (unlikely(anon_vma_prepare(vma)))
        goto oom;

    if (is_dsm_zero_pfn(pte_pfn(orig_pte))) {
        new_page = alloc_zeroed_user_highpage_movable(vma, address);
        if (!new_page)
            goto oom;
    } else {
        new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
        if (!new_page)
            goto oom;
        cow_user_page(new_page, old_page, address, vma);
    }
    __SetPageUptodate(new_page);

    if (mem_cgroup_newpage_charge(new_page, mm, GFP_KERNEL))
        goto oom_free_new;

    mmun_start = address & PAGE_MASK;
    mmun_end = mmun_start + PAGE_SIZE;
    mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);

    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (likely(pte_same(*page_table, orig_pte))) {
        if (old_page) {
            if (!PageAnon(old_page)) {
                dec_mm_counter(mm, MM_FILEPAGES);
                inc_mm_counter(mm, MM_ANONPAGES);
            }
        } else
            inc_mm_counter(mm, MM_ANONPAGES);
        flush_cache_page(vma, address, pte_pfn(orig_pte));
        entry = mk_pte(new_page, vma->vm_page_prot);
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);

        ptep_clear_flush(vma, address, page_table);
        page_add_new_anon_rmap(new_page, vma, address);
        set_pte_at_notify(mm, address, page_table, entry);
        update_mmu_cache(vma, address, page_table);
        if (old_page) {
            page_remove_rmap(old_page);
        }

        new_page = old_page;
        ret |= VM_FAULT_WRITE;
    } else
        mem_cgroup_uncharge_page(new_page);

    if (new_page)
        page_cache_release(new_page);
unlock:
    pte_unmap_unlock(page_table, ptl);
    if (mmun_end > mmun_start)
        mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
    if (old_page) {
        if ((ret & VM_FAULT_WRITE) && (vma->vm_flags & VM_LOCKED)) {
            lock_page(old_page); /* LRU manipulation */
            munlock_vma_page(old_page);
            unlock_page(old_page);
        }
        page_cache_release(old_page);
    }

    return ret;

oom_free_new:
    page_cache_release(new_page);
oom:
    if (old_page) {
        if (page_mkwrite) {
            unlock_page(old_page);
            page_cache_release(old_page);
        }
        page_cache_release(old_page);
    }
    return VM_FAULT_OOM;

unwritable_page:
    page_cache_release(old_page);
    return ret;
}

inline void dsm_release_pull_dpc(struct dsm_page_cache **dpc)
{
    atomic_dec(&(*dpc)->nproc);
    if (atomic_cmpxchg(&(*dpc)->nproc, 1, 0) == 1) {
        int i;

        for (i = 0; i < (*dpc)->svms.num; i++) {
            if (likely((*dpc)->pages[i]))
                page_cache_release((*dpc)->pages[i]);
        }
        dsm_dealloc_dpc(dpc);
    }
}

void dequeue_and_gup_cleanup(struct subvirtual_machine *svm)
{
    struct dsm_delayed_fault *ddf;
    struct dsm_page_cache *dpc;
    struct llist_node *head, *node;

    head = llist_del_all(&svm->delayed_faults);

    for (node = head; node; node = llist_next(node)) {
        ddf = llist_entry(node, struct dsm_delayed_fault, node);
        /* 
         * we need to hold the dpc to guarantee it doesn't disappear while we
         * do the if check
         */
        dpc = dsm_cache_get_hold(svm, ddf->addr);
        if (dpc && (dpc->tag & (PREFETCH_TAG | PULL_TRY_TAG))) {
            atomic_dec(&dpc->nproc);
            dsm_release_pull_dpc(&dpc);
        }
    }

    while (node) {
        ddf = llist_entry(node, struct dsm_delayed_fault, node);
        node = llist_next(node);
        free_dsm_delayed_fault_cache_elm(&ddf);
    }
}

static inline struct llist_node *llist_nodes_reverse(struct llist_node *llnode)
{
    struct llist_node *next, *tail = NULL;

    while (llnode) {
        next = llnode->next;
        llnode->next = tail;
        tail = llnode;
        llnode = next;
    }

    return tail;
}

int dsm_initiate_fault(struct mm_struct *mm, unsigned long addr, int write)
{
    int r;

    might_sleep();

    use_mm(mm);
    down_read(&mm->mmap_sem);
    r = get_user_pages(current, mm, addr, 1, write, 0, NULL, NULL);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    BUG_ON(r > 1);
    return r == 1;
}

static void heca_initiate_pull_gup(struct dsm_page_cache *dpc, int delayed)
{
    struct subvirtual_machine *svm = dpc->svm;
    struct memory_region *mr;

    if (delayed) {
        trace_delayed_initiated_fault(svm->dsm->dsm_id, svm->svm_id,
                -1, -1, dpc->addr, 0, dpc->tag);
    } else {
        trace_immediate_initiated_fault(svm->dsm->dsm_id, svm->svm_id,
                -1, -1, dpc->addr, 0, dpc->tag);
    }

    /* TODO: we do not allow deleting mrs; handle this case when we do */
    mr = search_mr_by_addr(svm, dpc->addr);
    if (unlikely(!mr))
        return;

    dsm_initiate_fault(svm->mm, dpc->addr, dpc->tag == PULL_TRY_TAG || 
            (~mr->flags & MR_SHARED));
}

static void dequeue_and_gup(struct subvirtual_machine *svm)
{
    struct dsm_delayed_fault *ddf;
    struct dsm_page_cache *dpc;
    struct llist_node *head, *node;

    head = llist_del_all(&svm->delayed_faults);
    head = llist_nodes_reverse(head);
    for (node = head; node; node = llist_next(node)) {
        ddf = llist_entry(node, struct dsm_delayed_fault, node);
        dpc = dsm_cache_get_hold(svm, ddf->addr);
        if (dpc) {
            /*
             * this might be another PULL_TRY or PREFETCH, if page has been
             * faulted, pushed and re-brought in the meanwhile. but no harm
             * in faulting it in anyway.
             */
            if (dpc->tag & (PREFETCH_TAG | PULL_TRY_TAG))
                heca_initiate_pull_gup(dpc, 1);
            dsm_release_pull_dpc(&dpc);
        }
    }
    for (node = head; node; node = llist_next(node)) {
        ddf = llist_entry(node, struct dsm_delayed_fault, node);
        free_dsm_delayed_fault_cache_elm(&ddf);
    }
}

void delayed_gup_work_fn(struct work_struct *w)
{
    struct subvirtual_machine *svm;
    svm = container_of(to_delayed_work(w), struct subvirtual_machine, 
            delayed_gup_work);
    dequeue_and_gup(svm);
}

static inline void queue_ddf_for_delayed_gup(struct dsm_delayed_fault *ddf,
        struct subvirtual_machine *svm)
{
    llist_add(&ddf->node, &svm->delayed_faults);
    schedule_delayed_work(&svm->delayed_gup_work, GUP_DELAY);
}

static int dsm_pull_req_success(struct page *page,
        struct dsm_page_cache *dpc)
{
    int i, found;
    trace_dsm_pull_req_complete(dpc->svm->dsm->dsm_id, dpc->svm->svm_id, -1,
            -1, dpc->addr, 0, dpc->tag);

    for (i = 0; i < dpc->svms.num; i++) {
        if (dpc->pages[i] == page)
            goto unlock;
    }
    BUG();

unlock:
    found = atomic_read(&dpc->found);
    if (found < 0) {
        if (atomic_cmpxchg(&dpc->found, found, i) != found)
            goto unlock;
        page_cache_get(page);
        lru_cache_add_anon(page);
        for (i = 0; i < dpc->svms.num; i++) {
            if (likely(dpc->pages[i]))
                SetPageUptodate(dpc->pages[i]);
        }
        trace_dsm_pull_req_success(dpc->svm->dsm->dsm_id, dpc->svm->svm_id, -1,
                -1, dpc->addr, 0, dpc->tag);
        unlock_page(dpc->pages[0]);
        lru_add_drain();

        /* try to delay faulting pages that were prefetched or pushed to us */
        if (dpc->tag & (PREFETCH_TAG | PULL_TRY_TAG)) {
            struct dsm_delayed_fault *ddf;

            //ddf = alloc_dsm_delayed_fault_cache_elm(dpc->addr);
            //if (likely(ddf))
            //    queue_ddf_for_delayed_gup(ddf, dpc->svm);
            //else
                heca_initiate_pull_gup(dpc, 0);
        }
    }

    return 1;
}

/* last failure should also account for the fault/gup refcount */
int dsm_pull_req_failure(struct dsm_page_cache *dpc)
{
    int found, i;

    trace_dsm_try_pull_req_complete_fail(dpc->svm->dsm->dsm_id,
            dpc->svm->svm_id, -1, -1, dpc->addr, 0, dpc->tag);

retry:
    /*
     * a successful request will set found >= 0. otherwise, the negative value
     * indicates the count of failed responses + 1. if everyone failed, we need
     * to clean up.
     */
    found = atomic_read(&dpc->found);
    if (found < 0) {
        if (atomic_cmpxchg(&dpc->found, found, found - 1) != found)
            goto retry;

        /* -found == svm_num <-> -(found-1) == svm_num+1 */
        if (found * -1 == dpc->svms.num) {
            for (i = 0; i < dpc->svms.num; i++) {
                if (likely(dpc->pages[i]))
                    SetPageUptodate(dpc->pages[i]);
            }
            unlock_page(dpc->pages[0]);
            dsm_cache_release(dpc->svm, dpc->addr);
            atomic_dec(&dpc->nproc);
        }
    }

    return -EFAULT;
}

static int dsm_pull_req_complete(struct tx_buf_ele *tx_e)
{
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct page *page = tx_e->wrk_req->dst_addr->mem_page;
    int r;

    r = unlikely(tx_e->dsm_buf->type == MSG_RES_PAGE_FAIL) ? 
        dsm_pull_req_failure(dpc) :
        dsm_pull_req_success(page, dpc);

    tx_e->wrk_req->dst_addr->mem_page = NULL;
    dsm_release_pull_dpc(&dpc);
    return r;
}

static struct page *dsm_get_remote_page(struct vm_area_struct *vma,
        unsigned long addr, struct dsm_page_cache *dpc,
        struct subvirtual_machine *fault_svm, struct memory_region *fault_mr,
        struct subvirtual_machine *remote_svm, int tag, int i,
        struct page_pool_ele *ppe)
{
    struct page *page = NULL;

    if (!dpc->pages[i]) {
        ppe = dsm_fetch_ready_ppe(remote_svm->ele);
        dpc->pages[i] = ppe ?
            ppe->mem_page : alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, addr);
    }
    page = dpc->pages[i];
    if (unlikely(!page))
        goto out;
    SetPageSwapBacked(page);

    trace_dsm_get_remote_page(fault_svm->dsm->dsm_id, fault_svm->svm_id,
            remote_svm->svm_id, fault_mr->mr_id, addr, addr - fault_mr->addr,
            tag);

    request_dsm_page(page, remote_svm, fault_svm, fault_mr, addr,
            dsm_pull_req_complete, tag, dpc, ppe);

out:
    return page;
}

static struct dsm_page_cache *dsm_cache_add_pushed(
        struct subvirtual_machine *fault_svm, struct memory_region *fault_mr,
        struct svm_list svms, unsigned long addr, struct page *page)
{
    struct dsm_page_cache *new_dpc = NULL, *found_dpc = NULL;
    int r, i;

    do {
        found_dpc = dsm_cache_get_hold(fault_svm, addr);
        if (unlikely(found_dpc))
            goto fail;

        if (!new_dpc) {
            /*
             * we always need PULL_TAG here, as we tried to push a page we were
             * previously maintaining.
             */
            new_dpc = dsm_alloc_dpc(fault_svm, addr, svms, 3, PULL_TAG);
            if (!new_dpc)
                goto fail;
            new_dpc->pages[0] = page;
            atomic_set(&new_dpc->found, 0);
        }

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (unlikely(r))
            goto fail;

        spin_lock_irq(&fault_svm->page_cache_spinlock);
        r = radix_tree_insert(&fault_svm->page_cache, addr, new_dpc);
        spin_unlock_irq(&fault_svm->page_cache_spinlock);
        radix_tree_preload_end();
        if (likely(!r)) {
            for_each_valid_svm(svms, i) {
                struct subvirtual_machine *remote_svm;

                remote_svm = find_svm(fault_svm->dsm, svms.ids[i]);
                if (likely(remote_svm)) {
                    dsm_claim_page(fault_svm, remote_svm, fault_mr, addr,
                            NULL, 0);
                    release_svm(remote_svm);
                }
            }
            return new_dpc;
        }
    } while (r != -ENOMEM);

fail:
    if (new_dpc)
        dsm_dealloc_dpc(&new_dpc);
    return found_dpc;
}

static struct dsm_page_cache *dsm_cache_add_send(
        struct subvirtual_machine *fault_svm, struct memory_region *fault_mr,
        struct svm_list svms, unsigned long norm_addr, int nproc, int tag,
        struct vm_area_struct *vma, pte_t orig_pte, pte_t *ptep, int alloc)
{
    struct dsm_page_cache *new_dpc = NULL, *found_dpc = NULL;
    struct page *page = NULL;
    struct page_pool_ele *ppe = NULL;
    int r;
    struct subvirtual_machine *first_svm = NULL;

    trace_dsm_cache_add_send(fault_svm->dsm->dsm_id, fault_svm->svm_id, -1,
            fault_mr->mr_id, norm_addr, norm_addr - fault_mr->addr, tag);

    do {
        found_dpc = dsm_cache_get_hold(fault_svm, norm_addr);
        if (unlikely(found_dpc))
            goto fail;

        if (likely(!new_dpc)) {
            new_dpc = dsm_alloc_dpc(fault_svm, norm_addr, svms,
                    svms.num + nproc, tag);
            if (!new_dpc)
                goto fail;
        }

        if (likely(!page)) {
            if (likely(svms.ids[0])) {
                first_svm = find_svm(fault_svm->dsm, svms.ids[0]);
                if (likely(first_svm))
                    ppe = dsm_fetch_ready_ppe(first_svm->ele);
            }
            if (ppe) {
                page = ppe->mem_page;
            } else if (alloc) {
                page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, norm_addr);
                if (unlikely(!page))
                    goto fail;
            } else {
                goto fail;
            }
            __set_page_locked(page);
            SetPageSwapBacked(page);
            new_dpc->pages[0] = page;
        }

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (unlikely(r))
            goto fail;

        spin_lock_irq(&fault_svm->page_cache_spinlock);
        r = radix_tree_insert(&fault_svm->page_cache, norm_addr, new_dpc);
        spin_unlock_irq(&fault_svm->page_cache_spinlock);
        radix_tree_preload_end();

        if (likely(!r)) {
            if (unlikely(!pte_same(*ptep, orig_pte))) {
                radix_tree_delete(&fault_svm->page_cache, norm_addr);
                goto fail;
            }
            if (likely(first_svm)) {
                dsm_get_remote_page(vma, norm_addr, new_dpc, fault_svm,
                        fault_mr, first_svm, tag, r, ppe);
                release_svm(first_svm);
            }
            for (r = 1; r < svms.num; r++) {
                struct subvirtual_machine *remote_svm;

                remote_svm = find_svm(fault_svm->dsm, svms.ids[r]);
                if (likely(remote_svm)) {
                    dsm_get_remote_page(vma, norm_addr, new_dpc, fault_svm,
                            fault_mr, remote_svm, tag, r, NULL);
                    release_svm(remote_svm);
                }
            }
            return new_dpc;
        }
    } while (r != -ENOMEM);

fail:
    if (new_dpc) {
        if (page) {
            ClearPageSwapBacked(page);
            unlock_page(page);
            if (ppe)
                dsm_ppe_clear_release(first_svm->ele, &ppe);
            else
                page_cache_release(page);
        }
        dsm_dealloc_dpc(&new_dpc);
    }
    if (first_svm)
        release_svm(first_svm);
    return found_dpc;
}

/*
 * return -1 on fault or stuff missing
 * return 1 if we send a request
 *  return 0 if dpc present
 *
 * TODO: no real need to normalize the address here, we're already receiving
 * a normalized one
 */
static int get_dsm_page(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *fault_svm, struct memory_region *mr,
        int tag)
{
    pte_t *pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct vm_area_struct *vma;
    unsigned long norm_addr = addr & PAGE_MASK;
    struct dsm_page_cache *dpc = NULL;
    int ret = 0;

    if (norm_addr < mr->addr || norm_addr >= mr->addr + mr->sz)
        goto out;

    dpc = dsm_cache_get(fault_svm, norm_addr);
    if (!dpc) {
        ret = -1;
        vma = find_vma(mm, addr);
        if (unlikely(!vma || vma->vm_start > addr))
            goto out;

        pgd = pgd_offset(mm, addr);
        if (unlikely(!pgd_present(*pgd)))
            goto out;

        pud = pud_offset(pgd, addr);
        if (unlikely(!pud_present(*pud)))
            goto out;

        pmd = pmd_offset(pud, addr);
        if (unlikely(pmd_none(*pmd)))
            goto out;

        if (unlikely(pmd_bad(*pmd))) {
            pmd_clear_bad(pmd);
            goto out;
        }
        if (unlikely(pmd_trans_huge(*pmd)))
            goto out;

        pte = pte_offset_map(pmd, addr);
        pte_entry = *pte;

        if (!pte_present(pte_entry) && !pte_none(pte_entry)) {
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e) && is_dsm_entry(swp_e)) {
                struct dsm_swp_data dsd;

                if (swp_entry_to_dsm_data(swp_e, &dsd) < 0)
                    goto out;

                if (dsd.flags & (DSM_INFLIGHT | DSM_PUSHING))
                    goto out;

                /*
                 * refcount for dpc:
                 *  +1 for every svm we send to
                 *  +1 for the fault that comes after fetching
                 */
                dsm_cache_add_send(fault_svm, mr, dsd.svms, norm_addr, 2,
                        tag, vma, pte_entry, pte, tag != PREFETCH_TAG);
                ret = 1;
            }
        }
    }

out:
    return ret;
}

/*
 * we were maintainers at some point, and we are certain to exit with all the
 * read copies we issued invalidated. we either discard the push operation
 * mid-way, or continue as usual after its completion. if some other maintainer
 * issued read copies in the meanwhile, it will invalidate them when we request
 * the page from it.
 */
static struct dsm_page_cache *convert_push_dpc(
        struct subvirtual_machine *fault_svm, struct memory_region *fault_mr,
        unsigned long norm_addr, struct dsm_swp_data dsd)
{
    struct dsm_page_cache *push_dpc, *dpc;
    struct page *page;
    unsigned long addr, bit;

    dpc = dsm_cache_get_hold(fault_svm, norm_addr);
    if (dpc)
        goto out;

    push_dpc = dsm_push_cache_get_remove(fault_svm, norm_addr);
    if (likely(push_dpc)) {
        page = push_dpc->pages[0];
        /*
         * decrease page refcount as to surrogate for all the svms that didn't
         * answer yet; then increase by two, as this is the correct, "found"
         * page.
         */
        do {
            bit = find_first_bit(&push_dpc->bitmap, push_dpc->svms.num);
            if (bit >= push_dpc->svms.num)
                break;
            if (test_and_clear_bit(bit, &push_dpc->bitmap))
                page_cache_release(page);
        } while(1);
        page_cache_get(page);
        page_cache_get(page); /* intentionally duplicate */

        SetPageSwapBacked(page);
        SetPageUptodate(page);
        ClearPageDirty(page);
        TestClearPageWriteback(page);

        addr = push_dpc->addr;
        if (atomic_cmpxchg(&push_dpc->nproc, 1, 0) == 1)
            dsm_dealloc_dpc(&push_dpc);
        dpc = dsm_cache_add_pushed(fault_svm, fault_mr, dsd.svms, addr, page);
    }

out:
    return dpc;
}

static int inflight_wait(pte_t *page_table, pte_t *orig_pte, swp_entry_t *entry,
        struct dsm_swp_data *dsd)
{
    pte_t pte;
    swp_entry_t swp_entry;
    int ret = 0;

    do {
        cond_resched();
        pte = *page_table;
        if (!pte_same(pte, *orig_pte)) {
            if (pte_present(pte)) {
                ret = 1;
                break;
            }

            if (!pte_none(pte) && !pte_file(pte)) {
                swp_entry = pte_to_swp_entry(pte);
                if (non_swap_entry(swp_entry) && is_dsm_entry(swp_entry) &&
                        dsm_swp_entry_same(swp_entry, *entry)) {
                    struct dsm_swp_data tmp_dsd;

                    if (swp_entry_to_dsm_data(swp_entry, &tmp_dsd) < 0) {
                        ret = -EFAULT;
                        goto out;
                    }

                    if (tmp_dsd.flags & DSM_INFLIGHT) {
                        continue;
                    } else {
                        *orig_pte = pte;
                        *entry = swp_entry;
                        *dsd = tmp_dsd;
                        break;
                    }
                }
            }
        }
    } while (1);

out:
    return ret;
}

static int dsm_fault_do_readahead(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *svm, struct memory_region *mr,
        struct dsm_page_cache *dpc)
{
    int max_retry = 20, cont_back = 1, cont_forward = 1, j = 1;

    do {
        if (cont_forward == 1)
            cont_forward = get_dsm_page(mm, addr + j * PAGE_SIZE, svm, mr,
                    PREFETCH_TAG);
        if (cont_back == 1) {
            if (addr > j * PAGE_SIZE)
                cont_back = get_dsm_page(mm, addr - j * PAGE_SIZE, svm, mr,
                        PREFETCH_TAG);
            else
                cont_back = 0;
        }
        if (trylock_page(dpc->pages[0])) {
            release_svm(svm);
            return 1;
        }
        j++;
    } while (j < max_retry && (cont_back == 1 || cont_forward == 1));

    return 0;
}

static int dsm_maintain_notify(struct subvirtual_machine *svm,
        struct memory_region *mr, unsigned long addr, u32 exclude_id)
{
    struct subvirtual_machine *owner;
    struct svm_list svms;
    int r = -EFAULT, i;

    rcu_read_lock();
    svms = dsm_descriptor_to_svms(mr->descriptor);
    rcu_read_unlock();

    for_each_valid_svm(svms, i) {
        /* the page returned home to us, its owners */
        if (svms.ids[i] == svm->svm_id) {
            r = 0;
            break;
        }

        if (svms.ids[i] == exclude_id)
            continue;

        owner = find_svm(svm->dsm, svms.ids[i]);
        if (likely(owner)) {
            r = dsm_claim_page(svm, owner, mr, addr, NULL, 0);
            release_svm(owner);
            break;
        }
    }

    return r;
}

static int do_dsm_page_fault(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry)
{
    struct dsm_swp_data dsd;
    struct subvirtual_machine *fault_svm;
    struct memory_region *fault_mr;
    unsigned long norm_addr = address & PAGE_MASK;
    spinlock_t *ptl;
    int ret = 0, found = -1, exclusive = 0, write,
        finalize_write = 0, read_fault = 0;
    struct dsm_page_cache *dpc = NULL;
    struct page *found_page, *swapcache = NULL;
    struct mem_cgroup *ptr;
    pte_t pte;
    u32 dsm_id, svm_id, mr_id; /* used only for trace record later */
    unsigned long shared_addr; /* used only for trace record later */
    struct dsm *dsm;

retry:
    /* if the data in the swp_entry is invalid, we have nothing to do */
    if (swp_entry_to_dsm_data(entry, &dsd) < 0)
        return VM_FAULT_ERROR;

    dsm = find_dsm(dsd.svms.dsm_id);
    if (unlikely(!dsm))
        return VM_FAULT_ERROR;

    fault_svm = find_local_svm_in_dsm(dsm, mm);
    if (unlikely(!fault_svm))
        return VM_FAULT_ERROR;

    fault_mr = search_mr_by_addr(fault_svm, norm_addr);
    if (unlikely(!fault_mr)) {
        release_svm(fault_svm);
        return VM_FAULT_ERROR;
    }

    if ((fault_mr->flags & MR_SHARED) && ~flags & FAULT_FLAG_WRITE)
        read_fault = 1;

    dsm_id = dsm->dsm_id;
    svm_id = fault_svm->svm_id;
    mr_id = fault_mr->mr_id;
    shared_addr = norm_addr - fault_mr->addr;
    trace_do_dsm_page_fault_svm(dsm_id, svm_id, -1, mr_id, norm_addr,
            shared_addr, dsd.flags);

    /*
     * If page is currently being pushed, halt the push, re-claim the page and
     * notify other nodes. If page is absent since we're answering a remote
     * fault, wait for it to finish before faulting ourselves.
     */
    if (unlikely(dsd.flags)) {
        if (dsd.flags & DSM_PUSHING) {
            dpc = convert_push_dpc(fault_svm, fault_mr, norm_addr, dsd);
            if (likely(dpc))
                goto lock;
        } else if (dsd.flags & DSM_INFLIGHT) {
            int inflight = inflight_wait(page_table, &orig_pte, &entry, &dsd);

            if (inflight) {
                if (inflight == -EFAULT) {
                    ret = VM_FAULT_ERROR;
                } else {
                    ret |= VM_FAULT_RETRY;
                    up_read(&mm->mmap_sem);
                }
                release_svm(fault_svm);
                goto out_no_dpc;
            }
        }
    }

    dpc = dsm_cache_get_hold(fault_svm, norm_addr);
    if (!dpc) {
        /*
         * refcount for dpc:
         *  +1 for every svm sent to
         *  +1 for the current do_dsm_page_fault
         *  +1 for the final, successful do_dsm_page_fault
         */
        dpc = dsm_cache_add_send(fault_svm, fault_mr, dsd.svms, norm_addr, 3,
                read_fault? READ_TAG : PULL_TAG, vma, orig_pte,
                page_table, 1);

        if (unlikely(!dpc)) {
            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (likely(pte_same(*page_table, orig_pte)))
                ret = VM_FAULT_OOM;
            pte_unmap_unlock(page_table, ptl);
            release_svm(fault_svm);
            goto out_no_dpc;
        }
        ret = VM_FAULT_MAJOR;
        count_vm_event(PGMAJFAULT);
        mem_cgroup_count_vm_event(mm, PGMAJFAULT);

    /*
     * we requested a read copy initially, but now we need to write. as a read
     * response is already underway, we will try to fault it in ASAP and then
     * go through dsm_write_fault to claim it. it's better than discarding it
     * and write faulting, as a page is already ready and page contents already
     * being transferred to us (CLAIM req is cheaper).
     */
    } else if (!read_fault && (dpc->tag & READ_TAG ||
            (dpc->tag & PREFETCH_TAG && fault_mr->flags & MR_SHARED))) {
        finalize_write = 1;
        goto lock;
    }

    /*
     * do not prefetch if we have the NOWAIT flag, as prefetch will be
     * triggered in the async PF
     */
    if (dpc->tag != PULL_TRY_TAG && flags & FAULT_FLAG_ALLOW_RETRY &&
            ~flags & FAULT_FLAG_RETRY_NOWAIT) {
        //if (dsm_fault_do_readahead(mm, norm_addr, fault_svm, fault_mr, dpc))
        //    goto resolve;
    }

    /*
     * KVM will send a NOWAIT flag and will freeze the faulting thread itself,
     * so we just re-throw immediately. Otherwise, we wait until the bitlock is
     * cleared, then re-throw the fault.
     */
lock:
    release_svm(fault_svm);
    if (!lock_page_or_retry(dpc->pages[0], mm, flags)) {
        ret |= VM_FAULT_RETRY;
        goto out;
    }

resolve:
    found = atomic_read(&dpc->found);
    if (unlikely(found < 0)) {
        unlock_page(dpc->pages[0]);
        /* caught a failed PULL_TRY dpc before it was released; retry */
        if (dpc->tag == PULL_TRY_TAG) {
            dsm_release_pull_dpc(&dpc);
            goto retry;
        }
        ret = VM_FAULT_ERROR;
        goto out;
    }

    /*
     * In this critical section, we lock the updated page (if it's the
     * first one, it was locked in advance), increment its refcount, the
     * pte_offset_map is locked and dpc refcount is already incremented.
     */
    found_page = dpc->pages[found];
    if (found)
        __set_page_locked(found_page);
    page_cache_get(found_page);

    swapcache = found_page;
    found_page = ksm_might_need_to_copy(found_page, vma, address);
    if (unlikely(!found_page)) {
        ret = VM_FAULT_OOM;
        found_page = swapcache;
        goto out_page;
    }

    if (mem_cgroup_try_charge_swapin(mm, found_page, GFP_KERNEL, &ptr)) {
        ret = VM_FAULT_OOM;
        goto out_page;
    }

    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (unlikely(!pte_same(*(page_table), orig_pte)))
        goto out_nomap;
    if (unlikely(!PageUptodate(found_page))) {
        ret = VM_FAULT_SIGBUS;
        goto out_nomap;
    }

    inc_mm_counter(mm, MM_ANONPAGES);
    pte = mk_pte(found_page, vma->vm_page_prot);

    /* this is delicate - has to handle the convert_push_dpc case too */
    write = !finalize_write &&
        (!read_fault || dpc->tag & (PULL_TRY_TAG | PULL_TAG));

    if (likely(reuse_dsm_page(found_page, norm_addr, dpc))) {
        if (write) {
            pte = maybe_mkwrite(pte_mkdirty(pte), vma);
            flags &= ~FAULT_FLAG_WRITE;
            ret |= VM_FAULT_WRITE;
        } else {
            pte = pte_mkclean(pte_wrprotect(pte));
        }
        exclusive = 1;
    }

    flush_icache_page(vma, found_page);
    set_pte_at(mm, address, page_table, pte);

    if (found_page == swapcache)
        do_page_add_anon_rmap(found_page, vma, address, exclusive);
    else
        page_add_new_anon_rmap(found_page, vma, address);
    mem_cgroup_commit_charge_swapin(found_page, ptr);

    unlock_page(found_page);
    if (found)
        unlock_page(dpc->pages[0]);

    if (found_page != swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }

    /*
     * if we're faulting for write in _this_ critical section (!finalize_write),
     * and the page cannot be reused.
     */
    if (write && flags & FAULT_FLAG_WRITE) {
        ret |= do_wp_dsm_page(mm, vma, address, page_table, pmd, ptl, pte,
                norm_addr, dpc);
        if (ret & VM_FAULT_ERROR)
            ret &= VM_FAULT_ERROR;
        goto out;
    }

    update_mmu_cache(vma, address, page_table);
    if (dpc->released == 1)
        dsm_cache_release(dpc->svm, dpc->addr);
    pte_unmap_unlock(pte, ptl);

    if (write)
        dsm_maintain_notify(dpc->svm, fault_mr, dpc->addr,dpc->svms.ids[found]);
    else
        dsm_flag_page_read(dpc->svm, dpc->addr, dpc->svms.ids[found]);
    page_cache_release(found_page);
    atomic_dec(&dpc->nproc);
    trace_do_dsm_page_fault_svm_complete(dsm_id, svm_id, -1, mr_id,
            norm_addr, shared_addr, dpc->tag);
    goto out;

out_nomap:
    pte_unmap_unlock(page_table, ptl);
    mem_cgroup_cancel_charge_swapin(ptr);

out_page:
    unlock_page(found_page);
    if (found)
        unlock_page(dpc->pages[0]);

    page_cache_release(found_page);
    if (found_page != swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }

out:
    if (likely(dpc)) {
        if (ret & VM_FAULT_RETRY && !(ret & VM_FAULT_ERROR))
            atomic_dec(&dpc->nproc);
        else
            dsm_release_pull_dpc(&dpc);
    }

out_no_dpc:
    if (unlikely(finalize_write && ~ret & (VM_FAULT_RETRY | VM_FAULT_ERROR))) {
        page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
        if (dsm_write_fault(mm, vma, address, pmd, page_table, ptl, flags) > 0){
            ret |= VM_FAULT_WRITE;
        } else {
            if (!pte_write(*page_table))
                ret |= VM_FAULT_ERROR;
            pte_unmap_unlock(page_table, ptl);
        }
    }
    return ret;
}

int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry)
{

#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
    return do_dsm_page_fault(mm, vma, address, page_table, pmd, flags,
            orig_pte, entry);

#else
    return 0;
#endif

}

int dsm_trigger_page_pull(struct dsm *dsm, struct subvirtual_machine *local_svm,
        struct memory_region *mr, unsigned long norm_addr)
{
    int r = 0;
    struct mm_struct *mm = local_svm->mm;

    down_read(&mm->mmap_sem);
    r = get_dsm_page(mm, norm_addr + mr->addr, local_svm, mr, PULL_TRY_TAG);
    up_read(&mm->mmap_sem);

    return r;
}

/*
 * we arrive with mmap_sem held and pte locked. if the address is ours, we leave
 * with mmap_sem still held, but pte unmapped and unlocked.
 */
int dsm_write_fault(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pmd_t *pmd, pte_t *ptep, spinlock_t *ptl,
        unsigned int flags)
{
    unsigned long addr = address & PAGE_MASK;
    struct subvirtual_machine *svm = NULL;
    struct memory_region *mr;
    struct page *page;
    struct dsm_pte_data pd;
    pte_t pte;
    struct dsm_page_cache *dpc = NULL;
    u32 maintainer_id = 0;

    svm = find_local_svm_from_mm(mm);
    if (!svm)
        return 0;

    mr = search_mr_by_addr(svm, addr);
    if (!mr) {
        release_svm(svm);
        return 0;
    }

    trace_dsm_write_fault(svm->dsm->dsm_id, svm->svm_id, -1, mr->mr_id, addr,
            addr - mr->addr, 0);

retry:
    pte = *ptep;
    if (unlikely(pte_write(pte))) {
        pte_unmap_unlock(ptep, ptl);
        goto out;
    }

    if (unlikely(!pte_present(pte))) {
        /*
         * this only happens on retries, and means someone else has requested
         * the page before us. so we do a full regular write fault.
         */
        pte_unmap_unlock(ptep, ptl);
        get_user_pages(current, mm, addr, 1, 1, 0, NULL, NULL);
        goto out;
    }

    /* should always succeed, as our vmas should never be VM_MIXEDMAP */
    page = vm_normal_page(vma, addr, pte);
    BUG_ON(!page);
    page_cache_get(page);

    dpc = dsm_cache_get_hold(svm, addr);
    if (unlikely(dpc)) {
        /* these should be handled in the first do_dsm_page_fault */
        BUG_ON(dpc->tag == PULL_TRY_TAG);

        if (dpc->tag == CLAIM_TAG) {
            pte_unmap_unlock(ptep, ptl);
            goto wait;
        }

        /* the pull req which brought the page hasn't been cleaned-up yet */
        dpc->tag = CLAIM_TAG;
    } else {
        int r = dsm_cache_add(svm, addr, 2, CLAIM_TAG, &dpc);

        if (unlikely(r < 0)) {
            if (r == -ENOMEM)
                return r;

            goto retry;
        }
    }

    if (!trylock_page(page)) {
        /*
         * if we can't lock the page, unlock the pte and resched. since we hold
         * the mmap_sem, the ptl will stay there and wait for us.
         */
        pte_unmap_unlock(ptep, ptl);
        page_cache_release(page);
        dsm_release_pull_dpc(&dpc);
        might_sleep();
        cond_resched();
        spin_lock(ptl);
        goto retry;
    }

    /*
     * we leave the critical section. as we invalidate the page copies,
     * someone else can take the page - any maintainer will answer requests
     * by order of arrival. but we ourselves will not answer any read
     * request, as the dpc is in-place.
     *
     * any subsequent write-fault will now encounter the CLAIM_TAG dpc and
     * know it can back away.
     */
    pte_unmap_unlock(ptep, ptl);

    /*
     * this races with try_discard_read_copy (which locks the page and checks
     * for dsm_cache_get), and with process_page_claim (which locks the pte
     * and checks for dsm_cache_get). so no locking needed.
     */
    if (dsm_lookup_page_read(svm, addr))
        maintainer_id = dsm_extract_page_read(svm, addr);

    if (maintainer_id) {
        struct subvirtual_machine *mnt_svm;

        mnt_svm = find_svm(svm->dsm, maintainer_id);
        if (!mnt_svm) {
            /*
             * TODO: the maintainer has left the cluster, and left us hanging.
             * we need to broadcast invalidation cluster-wide and assume
             * maintenance for the page. for now, we assume maintenance, even
             * though it will create several different copies of the page.
             */
            unlock_page(page);
            goto write;
        }

        dpc->redirect_svm_id = mnt_svm->svm_id;

        /* required as the page is locked, and will unlock only on claim_ack */
        page_cache_get(page);
        dsm_claim_page(svm, mnt_svm, mr, addr, page, 1);
        release_svm(mnt_svm);

    } else {
        dsm_invalidate_readers(svm, addr, 0);

        /*
         * TODO: with strict coherency policy, only the last ACK from readers
         * will unlock the page. meanwhile, it costs very little to leave this
         * here (+2 atomic operations)
         */
        unlock_page(page);
    }

    /* by now, all read copies have been invalidated at least once */
wait:
    up_read(&mm->mmap_sem);
    wait_on_page_locked(page);

    /*
     * we must release the lock before sleeping, and now re-grab it and
     * re-query the page table. otherwise a nasty edge case might occur when
     * someone tries to grab the lock for write, while a page extraction
     * request is processed (requiring the lock for read) before the ACK.
     */
    down_read(&mm->mmap_sem);
    if (unlikely(dsm_extract_pte_data(&pd, mm, address))) {
        up_read(&mm->mmap_sem);
        return 0;
    }
    ptep = pd.pte;

write:
    spin_lock(ptl);
    if (unlikely(!pte_same(*ptep, pte))) {
        page_cache_release(page);
        dsm_release_pull_dpc(&dpc);
        goto retry;
    }
    pte = pte_mkyoung(maybe_mkwrite(pte_mkdirty(pte), vma));
    if (ptep_set_access_flags(vma, addr, ptep, pte, 1))
        update_mmu_cache(vma, addr, ptep);
    page_cache_release(page);
    pte_unmap_unlock(ptep, ptl);

    dsm_maintain_notify(svm, mr, addr, maintainer_id);

    /* compatible with a pre-existing dpc, and with a newly created dpc */
    dsm_cache_release(svm, addr);
    dsm_release_pull_dpc(&dpc);

out:
    release_svm(svm);
    return 1;
}

