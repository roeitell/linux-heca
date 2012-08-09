/*
 * dsm_page_request.c
 *
 *  Created on: 1 Aug 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

struct dsm_pte_data {
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
};

inline void dsm_push_finish_notify(struct page *page)
{
    struct zone *zone = page_zone(page);
    wait_queue_head_t *waitqueue =
        &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
    rotate_reclaimable_page(page);
    ClearPageDirty(page);
    TestClearPageWriteback(page);
    __wake_up_bit(waitqueue, &page->flags, PG_writeback);
}
EXPORT_SYMBOL(dsm_push_finish_notify);

static int dsm_push_cache_add(struct dsm_page_cache *dpc,
        struct subvirtual_machine *svm, unsigned long addr)
{
    struct dsm_page_cache *rb_dpc;
    struct rb_node **new, *parent = NULL;
    int r = 0;

    write_seqlock(&svm->push_cache_lock);
    for (new = &svm->push_cache.rb_node; *new;) {
        rb_dpc = rb_entry(*new, struct dsm_page_cache, rb_node);
        parent = *new;
        BUG_ON(!rb_dpc);
        if (addr < rb_dpc->addr)
            new = &(*new)->rb_left;
        else if (addr > rb_dpc->addr)
            new = &(*new)->rb_right;
        else {
            r = -EEXIST;
            goto out;
        }
    }

    rb_link_node(&dpc->rb_node, parent, new);
    rb_insert_color(&dpc->rb_node, &svm->push_cache);

out:
    write_sequnlock(&svm->push_cache_lock);
    return r;
}

/* FIXME: push_cache lookup needs rcu protection */
static struct dsm_page_cache *dsm_push_cache_lookup(
        struct subvirtual_machine *svm, unsigned long addr)
{
    struct dsm_page_cache *dpc = NULL;
    struct rb_node *node;
    int seq;

    do {
        seq = read_seqbegin(&svm->push_cache_lock);
        for (node = svm->push_cache.rb_node; node; dpc = NULL) {
            dpc = rb_entry(node, struct dsm_page_cache, rb_node);
            BUG_ON(!dpc);
            if (addr < dpc->addr)
                node = node->rb_left;
            else if (addr > dpc->addr)
                node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&svm->push_cache_lock, seq));

    return dpc;
}

static struct dsm_page_cache *dsm_push_cache_get(struct subvirtual_machine *svm,
        unsigned long addr, struct subvirtual_machine *remote_svm)
{
    struct rb_node *node;
    struct dsm_page_cache *dpc = NULL;
    int seq, i;

    BUG_ON(!svm);

    do {
        seq = read_seqbegin(&svm->push_cache_lock);
        for (node = svm->push_cache.rb_node; node; dpc = NULL) {
            dpc = rb_entry(node, struct dsm_page_cache, rb_node);
            BUG_ON(!dpc);
            if (addr < dpc->addr)
                node = node->rb_left;
            else if (addr > dpc->addr)
                node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&svm->push_cache_lock, seq));

    if (likely(dpc) && remote_svm) {
        for (i = 0; i < dpc->svms.num; i++) {
            if (dpc->svms.pp[i] == remote_svm) {
                if (likely(test_and_clear_bit(i, &dpc->bitmap) &&
                        atomic_add_unless(&dpc->nproc, 1, 0))) {
                    goto out;
                }
                break;
            }
        }
        dpc = NULL;
    }

out: 
    return dpc;
}

inline void dsm_push_cache_release(struct subvirtual_machine *svm,
        struct dsm_page_cache **dpc, int lock)
{
    page_cache_release((*dpc)->pages[0]);
    if (likely(lock)) {
        write_seqlock(&svm->push_cache_lock);
        rb_erase(&(*dpc)->rb_node, &svm->push_cache);
        write_sequnlock(&svm->push_cache_lock);
    } else {
        /* !lock only when traversing push_cache when removing svms */
        rb_erase(&(*dpc)->rb_node, &svm->push_cache);
    }
    dsm_push_finish_notify((*dpc)->pages[0]);
    dsm_dealloc_dpc(dpc);
}

struct dsm_page_cache *dsm_push_cache_get_remove(struct subvirtual_machine *svm,
        unsigned long addr)
{
    struct dsm_page_cache *dpc;
    struct rb_node *node;

    write_seqlock(&svm->push_cache_lock);
    for (node = svm->push_cache.rb_node; node; dpc = 0) {
        dpc = rb_entry(node, struct dsm_page_cache, rb_node);
        if (addr < dpc->addr)
            node = node->rb_left;
        else if (addr > dpc->addr)
            node = node->rb_right;
        else
            break;
    }
    if (likely(dpc)) {
        rb_erase(&dpc->rb_node, &svm->push_cache);
        dpc->bitmap = 0;
    }
    write_sequnlock(&svm->push_cache_lock);

    return dpc;
}
EXPORT_SYMBOL(dsm_push_cache_get_remove);

static int dsm_extract_pte_data(struct dsm_pte_data *pd, struct mm_struct *mm,
        unsigned long addr) 
{
    int i;

    BUG_ON(!mm);
    BUG_ON(!pd);

retry: 
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
    if (unlikely(pmd_none(*(pd->pmd)))) {
        if (!__pte_alloc(mm, pd->vma, pd->pmd, addr))
            goto retry;
        return -4;
    }
    if (unlikely(pmd_bad(*(pd->pmd)))) {
        pmd_clear_bad(pd->pmd);
        return -5;
    }

    if (unlikely(pmd_trans_huge(*(pd->pmd)))) {
        spin_lock(&mm->page_table_lock);
        i = pmd_trans_splitting(*(pd->pmd));
        spin_unlock(&mm->page_table_lock);

        if (unlikely(i))
            wait_split_huge_page(pd->vma->anon_vma, pd->pmd);
        else
            split_huge_page_pmd(mm, pd->pmd);
        goto retry;
    }

    pd->pte = pte_offset_map(pd->pmd, addr);
    return !pd->pte;
}

static u32 dsm_extract_handle_missing_pte(struct subvirtual_machine *local_svm,
        struct mm_struct *mm, unsigned long addr, pte_t pte_entry,
        struct dsm_pte_data *pd)
{
    swp_entry_t swp_e;
    struct dsm_swp_data dsd;
    struct dsm_page_cache *dpc =NULL;
    /* first time dealing with this addr? */
    if (pte_none(pte_entry))
        goto fault_page;

    /* page could be swapped to disk */
    swp_e = pte_to_swp_entry(pte_entry);
    if (!non_swap_entry(swp_e))
        goto fault_page;

    if (is_migration_entry(swp_e)) {
        migration_entry_wait(mm, pd->pmd, addr);
        goto fault_page;
    }

    /* not a swap entry or a migration entry, must be ours */
    BUG_ON(!is_dsm_entry(swp_e));
    if (swp_entry_to_dsm_data(swp_e, &dsd) < 0)
        BUG();
    // we check if we are already pulling
    dpc = dsm_cache_get(local_svm, addr);
    if (dpc)
        goto fault_page;
    // we can only redirect if we have one location to redirect to!
    //FIXME enable RAIM support
    BUG_ON(dsd.svms.num != 1);
    return dsd.svms.pp[0]->svm_id;

    //FIXME: we do not support mirrored push with redirect... so no active active passive scenario


//    if (unlikely(dsd.flags)) {
//        /*
//         * FIXME: unhandled; we need to stop the push process, and reclaim the
//         * page, so we can answer the fault. an interesting question is what to
//         * do if we're pushing to the faulting machine anyway.
//         */
//        if (dsd.flags & DSM_PUSHING)
//            BUG();
//
//        /* we're answering another fault, we can't answer this one */
//        else if (dsd.flags & DSM_INFLIGHT)
//            return;
//    }

fault_page:
    /* we already use the mm and we already own the mm semaphore */

    return 0 ;
}

static struct page *dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr, pte_t **return_pte, u32 *svm_id)
{
    spinlock_t *ptl;
    int r = 0;
    struct page *page;
    struct dsm_pte_data pd;
    pte_t pte_entry;
    *svm_id = 0;
    
retry:
    page = NULL;
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
        pte_unmap_unlock(pd.pte, ptl);
        goto retry;
    }
    if (unlikely(!pte_present(pte_entry))) {
        *svm_id = dsm_extract_handle_missing_pte(local_svm, mm, addr, pte_entry,
                &pd);

        if (*svm_id) {
            set_pte_at(mm, addr, pd.pte,
                    dsm_descriptor_to_pte(remote_svm->descriptor, 0));
            pte_unmap_unlock(pd.pte, ptl);
            goto out;
        } else {
            pte_unmap_unlock(pd.pte, ptl);
            get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
            goto retry;
        }
    }

    page = vm_normal_page(pd.vma, addr, *(pd.pte));
    if (!page) {
        /* DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf */
        if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;

        page = pte_page(*(pd.pte));
    }

    if (unlikely(PageTransHuge(page))) {
        if (!PageHuge(page) && PageAnon(page)) {
            pte_unmap_unlock(pd.pte, ptl);
            if (unlikely(split_huge_page(page)))
                goto bad_page;
            goto retry;
        }
    }

    if (unlikely(PageKsm(page))) {
        r = ksm_madvise(pd.vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE,
                &(pd.vma->vm_flags));
        if (r) /* DSM1 : better ksm error handling required. */
            goto bad_page;
    }


    page_cache_get(page);

    flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
    ptep_clear_flush_notify(pd.vma, addr, pd.pte);
    set_pte_at(mm, addr, pd.pte, 
            dsm_descriptor_to_pte(remote_svm->descriptor, DSM_INFLIGHT));

    page_remove_rmap(page);
    page_cache_release(page);
    dec_mm_counter(mm, MM_ANONPAGES);

    *return_pte = pd.pte;

    pte_unmap_unlock(pd.pte, ptl);
out: 
    return page;
    
bad_page: 
    pte_unmap_unlock(pd.pte, ptl);
    return NULL;
}

static struct page *try_dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr, pte_t **return_pte)
{
    struct page *page;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct dsm_pte_data pd;
    int clear_pte_flag = 0, active = 0;
    spinlock_t *ptl = NULL;

retry: 
    page = NULL;
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    dpc = dsm_push_cache_get(local_svm, addr, remote_svm);
    if (unlikely(!dpc))
        goto out;

    page = dpc->pages[0];
    BUG_ON(!page);

    /* page has been taken in the meanwhile, bail out */
    if (unlikely(PageActive(page))) {
        active = 1;
        goto noop;

    /* first response to arrive and grab the pte lock */
    } else if (pte_present(pte_entry)) {
        /* make sure shrink_page_list is finished with this page */
        lock_page(page);
        pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
            unlock_page(page);
            pte_unmap_unlock(pd.pte, ptl);
            goto retry;
        }

        flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
        ptep_clear_flush_notify(pd.vma, addr, pd.pte);
        set_pte_at(mm, addr, pd.pte, dsm_descriptor_to_pte(dpc->tag,
                    (dpc->svms.num == 1)? 0 : DSM_PUSHING));
        page_remove_rmap(page);
        page_cache_release(page);
        dec_mm_counter(mm, MM_ANONPAGES);
        pte_unmap_unlock(pd.pte, ptl);
        unlock_page(page);
    } else {
        if (unlikely(pte_none(pte_entry))) {
            page = NULL;
            goto noop;
        }

        swp_e = pte_to_swp_entry(pte_entry);
        if (unlikely(!non_swap_entry(swp_e) || !is_dsm_entry(swp_e)))
            BUG_ON(page);

        /* signal that this is not the first response */
        clear_pte_flag = 1;
    }

noop: 
    atomic_dec(&dpc->nproc);
    if (find_first_bit(&dpc->bitmap, dpc->svms.num) >= dpc->svms.num && 
            atomic_cmpxchg(&dpc->nproc, 1, 0) <= 1) {
        if (likely(page)) {
            if (likely(clear_pte_flag)) {
                pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
                if (likely(pte_same(*(pd.pte), pte_entry)))
                    dsm_clear_swp_entry_flag(mm,addr,pd.pte,DSM_PUSHING_BITPOS);
                pte_unmap_unlock(pd.pte, ptl);
            }
            dsm_push_cache_release(local_svm, &dpc, 1);
        } else {
            write_seqlock(&local_svm->push_cache_lock);
            rb_erase(&dpc->rb_node, &local_svm->push_cache);
            write_sequnlock(&local_svm->push_cache_lock);
            dsm_dealloc_dpc(&dpc);
        }
    }

    *return_pte = pd.pte;

out: 
    return active? NULL : page;
}

struct page *dsm_extract_page_from_remote(struct dsm *dsm,
        struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, unsigned long addr, u16 tag,
        pte_t **pte, u32 * svm_id) {
    struct mm_struct *mm;
    struct page *page = NULL;

    BUG_ON(!local_svm);
    BUG_ON(!local_svm->priv);

    mm = local_svm->priv->mm;
    BUG_ON(!mm);

    use_mm(mm);
    down_read(&mm->mmap_sem);
    page = (tag == TRY_REQUEST_PAGE)?
        try_dsm_extract_page(local_svm, remote_svm, mm, addr, pte) : 
        dsm_extract_page(local_svm, remote_svm, mm, addr, pte, svm_id);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    return page;
}
EXPORT_SYMBOL(dsm_extract_page_from_remote);

/* this function is purely for development, used in the PUSH ioctl */
struct page *dsm_find_normal_page(struct mm_struct *mm, unsigned long addr)
{
    struct page *page = NULL;
    struct dsm_pte_data pd;
    pte_t pte_entry, *pte;
    spinlock_t *ptl;

    if (dsm_extract_pte_data(&pd, mm, addr))
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
EXPORT_SYMBOL(dsm_find_normal_page);

int dsm_prepare_page_for_push(struct subvirtual_machine *local_svm,
        struct svm_list svms, struct page *page, unsigned long addr,
        struct mm_struct *mm, u32 descriptor)
{
    struct dsm_pte_data pd;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry, *pte;
    spinlock_t *ptl;
    int i, r;

    BUG_ON(!local_svm);

    /*
     * We only change pte when the first response returns, in order to keep the
     * page accessible; therefore someone might ask us to re-push a page before
     * any response has even returned.
     */
    if (dsm_push_cache_lookup(local_svm, addr))
        return -EEXIST;

retry:
    dpc = dsm_alloc_dpc(local_svm, addr, svms, 1, descriptor);
    if (unlikely(!dpc))
        return -ENOMEM;

    /* we're trying to swap out an active page, everything should be here */
    dsm_extract_pte_data(&pd, mm, addr);
    BUG_ON(!pd.pte);
    pte_entry = *(pd.pte);
    BUG_ON(!pte_present(pte_entry));

    pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*pte, pte_entry))) {
        pte_unmap_unlock(pte, ptl);
        goto retry;
    }

    if (unlikely(PageTransHuge(page) && !PageHuge(page) && PageAnon(page))) {
        if (unlikely(split_huge_page(page)))
            goto bad_page;
    }

    if (unlikely(PageKsm(page))) {
        if (ksm_madvise(pd.vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE,
                &pd.vma->vm_flags))
            goto bad_page;
    }

    r = dsm_push_cache_add(dpc, local_svm, addr);
    if (unlikely(r))
        goto bad_page;

    dpc->bitmap = 0;
    dpc->pages[0] = page;

    /*
     * refcount is as follows:
     *  1 for being in dpc (released upon dealloc)
     *  1 for every svm sent to (released on release_ppe)
     */
    page_cache_get(page);
    for_each_valid_svm(svms, i) {
        page_cache_get(page);
        dpc->bitmap += (1 << i);
    }

    /*
     * PageWriteback signals shrink_page_list it can either synchronously wait
     * for op to complete, or just ignore the page and continue. It also gives
     * __isolate_lru_page a chance to bail.
     */
    SetPageDirty(page);
    TestSetPageWriteback(page);

    pte_unmap_unlock(pte, ptl);
    return 0;
    
bad_page: 
    dsm_dealloc_dpc(&dpc);
    pte_unmap_unlock(pte, ptl);
    return -EFAULT;
}
EXPORT_SYMBOL(dsm_prepare_page_for_push);

int dsm_cancel_page_push(struct subvirtual_machine *svm, unsigned long addr,
        struct page *page)
{
    struct dsm_page_cache *dpc = dsm_push_cache_get(svm, addr, NULL);
    int i;

    if (unlikely(!dpc))
        return -1;

    for_each_valid_svm(dpc->svms, i)
        page_cache_release(page);
    dsm_push_cache_release(svm, &dpc, 1);

    return 0;
}
EXPORT_SYMBOL(dsm_cancel_page_push);

/*
 * Local node A sends a blue page to node B, the dsm_swp_entry on node A points to B.  Node C requests the page from Node A,
 * Node A forwards the request to Node B, which sends the page to Node C and sets the dsm_swp_entry to Node C.
 *
 * When Node D requests the page from Node A, the request needs to be passed along the whole chain until hitting Node C, which can
 * process the request and send the page.
 *
 * This function will allow the updating of PTE values along the chain.  Node C will send the update command to
 * Node A, it will update the dsm_swap_entry to point to Node C, then forward the command to each Node along the chain.
 *
 * Node D then requests the page from Node A, the request is now passed straight to Node C.  It is asynchronous, if Node A is not
 * updated on time, the next Node can still pass the request along fine - either to the next node or directly to the final.
 *
 */
int dsm_update_pte_entry(struct dsm_message *msg) // DSM1 - update all code
{
    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct dsm *dsm;
    struct subvirtual_machine *svm;
    swp_entry_t swp_e;
    struct mm_struct *mm;
    u32 svm_id;

    svm_id = msg->dest_id;
    dsm = find_dsm(msg->dsm_id);
    BUG_ON(!dsm);

    svm = find_svm(dsm, svm_id);
    BUG_ON(!svm);

    mm = svm->priv->mm;
    down_read(&mm->mmap_sem);
    retry:

    vma = find_vma(mm, msg->req_addr);
    if (!vma || vma->vm_start > msg->req_addr)
        goto out;

    pgd = pgd_offset(mm, msg->req_addr);
    if (!pgd_present(*pgd))
        goto out;

    pud = pud_offset(pgd, msg->req_addr);
    if (!pud_present(*pud))
        goto out;

    pmd = pmd_offset(pud, msg->req_addr);
    BUG_ON(pmd_trans_huge(*pmd));
    if (!pmd_present(*pmd))
        goto out;

    pte = pte_offset_map_lock(mm, pmd, msg->req_addr, &ptl);
    pte_entry = *pte;

    if (!pte_present(pte_entry)) {
        if (pte_none(pte_entry)) {
            set_pte_at(mm, msg->req_addr, pte,
                    dsm_descriptor_to_pte(svm->descriptor, 0));
        } else {
            swp_e = pte_to_swp_entry(pte_entry);
            if (!non_swap_entry(swp_e)) {
                if (is_dsm_entry(swp_e)) {
                    // store old dest
                    struct dsm_swp_data old;

                    swp_entry_to_dsm_data(pte_to_swp_entry(pte_entry), &old);
                    BUG_ON(!old.dsm);

                    if (old.dsm->dsm_id != dsm->dsm_id && old.svms.pp[0]->svm_id != svm_id) {
                        // update pte
                        set_pte_at(mm, msg->req_addr, pte,
                                dsm_descriptor_to_pte(svm->descriptor, 0));

                        // forward msg
                        // DSM1: fwd message RDMA function call.
                        // old.dsm_id, old.svm_id.
                    }
                } else if (is_migration_entry(swp_e)) {
                    pte_unmap_unlock(pte, ptl);

                    migration_entry_wait(mm, pmd, msg->req_addr);

                    goto retry;
                } else {
                    printk("[*] SWP_ENTRY - not dsm or migration.\n");
                    BUG();
                }
            } else {
                printk("[*] in swap no need to update\n");
            }
        }
    }

    pte_unmap_unlock(pte, ptl);

out:
    up_read(&mm->mmap_sem);
    release_svm(svm);

    return r;

}
EXPORT_SYMBOL(dsm_update_pte_entry);

static inline int wait_for_page_push(void *x)
{
    schedule();
    return 0;
}

/*
 * Return 0 => page dsm or not dsm_remote => try to swap out
 * Return 1 => page is dsm => do not swap out (not necessarily scheduled yet to
 *             be pushed back, could only be done in next cycle)
 */
static int _push_back_if_remote_dsm_page(struct page *page)
{
    struct anon_vma *anon_vma;
    struct anon_vma_chain *avc;
    int ret = 0;

    if (unlikely(!get_dsm_module_state()))
        goto out;

    /* don't push pages that belong to more than one process, avoid pitfalls */
    if (page_mapcount(page) > 1)
        goto out;

    anon_vma = page_lock_anon_vma(page);
    if (!anon_vma)
        goto out;

    /* note: should actually find only one relevant vma */
    list_for_each_entry(avc, &anon_vma->head, same_anon_vma)
    {
        struct vm_area_struct *vma = avc->vma;
        unsigned long address;
        struct subvirtual_machine *svm;
        struct memory_region *mr;

        address = page_address_in_vma(page, vma);
        if (address == -EFAULT)
            continue;

        svm = find_local_svm(vma->vm_mm);
        if (!svm)
            continue;

        mr = search_mr(svm->dsm, address);
        if (!mr || mr->local == LOCAL) {
            release_svm(svm);
            continue;
        }

        BUG_ON(address < svm->priv->offset);
        dsm_request_page_pull(svm->dsm, svm, page, address, vma->vm_mm, mr);

        release_svm(svm);
        if (PageSwapCache(page))
            try_to_free_swap(page);

        ret = 1;
        break;
    }

    page_unlock_anon_vma(anon_vma);
out:
    return ret;
}

int push_back_if_remote_dsm_page(struct page *page)
{
    return _push_back_if_remote_dsm_page(page);
}

