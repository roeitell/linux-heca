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

static struct dsm_page_cache *dsm_push_cache_add(struct subvirtual_machine *svm,
        unsigned long addr, struct svm_list svms, int nproc, u32 descriptor)
{
    struct dsm_page_cache *dpc = NULL, *rb_dpc;
    struct rb_node **new, *parent = NULL;

    dpc = dsm_alloc_dpc(svm, addr, svms, 1, descriptor);
    if (unlikely(!dpc))
        goto out;
    dpc->bitmap = (1 << nproc) - 1;

    write_seqlock(&svm->push_cache_lock);
    for (new = &svm->push_cache.rb_node; *new;) {
        rb_dpc = rb_entry(*new, struct dsm_page_cache, rb_node);
        parent = *new;
        BUG_ON(!rb_dpc);
        if (addr < rb_dpc->addr)
            new = &(*new)->rb_left;
        else if (addr > rb_dpc->addr)
            new = &(*new)->rb_right;
        else
            goto exist;
    }

    rb_link_node(&dpc->rb_node, parent, new);
    rb_insert_color(&dpc->rb_node, &svm->push_cache);
    write_sequnlock(&svm->push_cache_lock);

out:
    return dpc;

exist:
    write_sequnlock(&svm->push_cache_lock);
    if (dpc)
        dsm_dealloc_dpc(&dpc);
    return dpc;
}

static struct dsm_page_cache *dsm_push_cache_get(struct subvirtual_machine *svm,
        unsigned long addr, struct subvirtual_machine *remote_svm)
{
    struct rb_node *node;
    struct dsm_page_cache *dpc = NULL;
    int seq, i;

    BUG_ON(!svm);

    rcu_read_lock();
    do {
        seq = read_seqbegin(&svm->push_cache_lock);
        for (node = svm->push_cache.rb_node; node; dpc = 0) {
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
    rcu_read_unlock();
    return dpc;
}

static inline void dsm_push_cache_release(struct subvirtual_machine *svm,
        struct dsm_page_cache **dpc)
{
    write_seqlock(&svm->push_cache_lock);
    rb_erase(&(*dpc)->rb_node, &svm->push_cache);
    write_sequnlock(&svm->push_cache_lock);
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
        __pte_alloc(mm, pd->vma, pd->pmd, addr);
        goto retry;
    }
    if (unlikely(pmd_bad(*(pd->pmd)))) {
        pmd_clear_bad(pd->pmd);
        return -4;
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

static inline void dsm_extract_do_gup(struct page *page, struct mm_struct *mm,
        unsigned long addr)
{
    use_mm(mm);
    down_read(&mm->mmap_sem);
    get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);
}

static struct page *dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr, pte_t **return_pte)
{
    spinlock_t *ptl;
    int r = 0, i;
    struct dsm_page_cache *dpc = NULL;
    struct page *page = NULL;
    struct dsm_pte_data pd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    
retry:
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    if (unlikely(!pte_present(pte_entry))) {
        if (pte_none(pte_entry))
            goto chain_fault;

        else {
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e)) {
                if (is_dsm_entry(swp_e)) {
                    dpc = dsm_cache_get_hold(local_svm, addr);
                    if (unlikely(!dpc))

                        goto chain_fault;

                    if (dpc->tag == PULL_TAG || dpc->tag == PULL_TRY_TAG) {
                        wait_on_page_locked_killable(dpc->pages[0]);
                    } else if (dpc->tag == PREFETCH_TAG) {
                        i = atomic_read(&dpc->found);
                        if (i >= 0) {
                            page = dpc->pages[i];
                            if (likely(page))
                                dsm_extract_do_gup(page, mm, addr);
                        }
                    }
                    atomic_dec(&dpc->nproc);
                    if (atomic_cmpxchg(&dpc->nproc, 1, 0) == 1) {
                        page_cache_release( dpc->pages[0]);
                        dsm_dealloc_dpc(&dpc);
                    }
                    goto retry;
                } else if (is_migration_entry(swp_e)) {
                    migration_entry_wait(mm, pd.pmd, addr);
                    goto retry;
                }
                BUG();
            } else {
chain_fault: 
                dsm_extract_do_gup(page, mm, addr);
                goto retry;
            }
        }
    }

    pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
        pte_unmap_unlock(pd.pte, ptl);
        goto retry;
    }
    page = vm_normal_page(pd.vma, addr, *(pd.pte));
    if (!page) {
// DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf
        if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;

        page = pte_page(*(pd.pte));
    }

    if (unlikely(PageTransHuge(page))) {
        printk("[dsm_extract_page] we have a huge page \n");
        if (!PageHuge(page) && PageAnon(page)) {
            if (unlikely(split_huge_page(page))) {
                printk("[dsm_extract_page] failed at splitting page \n");
                goto bad_page;
            }

        }
    }
    if (unlikely(PageKsm(page))) {
        printk("[dsm_extract_page] KSM page\n");

        r = ksm_madvise(pd.vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE,
                &(pd.vma->vm_flags));

        if (r) {
            printk("[dsm_extract_page] ksm_madvise ret : %d\n", r);

            // DSM1 : better ksm error handling required.
            goto bad_page;
        }
    }

    if (unlikely(!trylock_page(page))) {
        printk("[dsm_extract_page] cannot lock page\n");
        goto bad_page;
    }

    page_cache_get(page);
    flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
    ptep_clear_flush_notify(pd.vma, addr, pd.pte);
    set_pte_at(mm, addr, pd.pte,
            swp_entry_to_pte(dsm_descriptor_to_swp_entry( remote_svm->descriptor, DSM_INFLIGHT)));
    page_remove_rmap(page);
    page_cache_release(page);

    dec_mm_counter(mm, MM_ANONPAGES);
    unlock_page(page);
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
    struct page *page = NULL;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct dsm_pte_data pd;
    int change_pte = 0, active = 0, unlock;
    spinlock_t *ptl = NULL;

retry: 
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    dpc = dsm_push_cache_get(local_svm, addr, remote_svm);
    if (unlikely(!dpc))
        goto out;

    page = dpc->pages[0];
    BUG_ON(!page);
    if (unlikely(PageActive(page))) {
        active = 1;
        goto noop;

    } else if (pte_present(pte_entry)) {
        if (likely(trylock_page(page))) {

            pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
            if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
                pte_unmap_unlock(pd.pte, ptl);
                unlock_page(page);
                goto retry;
            }
            flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
            ptep_clear_flush_notify(pd.vma, addr, pd.pte);
            set_pte_at(mm, addr, pd.pte,
                    swp_entry_to_pte(dsm_descriptor_to_swp_entry(
                    dpc->tag, (dpc->svms.num == 1)? 0 : DSM_PUSHING)));
            dsm_stats_inc_cond(&local_svm->svm_sysfs.nb_push_success,
                    dpc->svms.num == 1);
            page_remove_rmap(page);
            dec_mm_counter(mm, MM_ANONPAGES);
            pte_unmap_unlock(pd.pte, ptl);
            unlock_page(page);
        } else if (dpc->svms.num > 1) {
            change_pte = 1;
        }

    } else {
        if (unlikely(pte_none(pte_entry))) {
            page = NULL;
            goto noop;
        }

        BUG_ON(pte_file(pte_entry));
        swp_e = pte_to_swp_entry(pte_entry);
        if (unlikely(!non_swap_entry(swp_e) || !is_dsm_entry(swp_e)))
            BUG_ON(page);

        change_pte = 1;
    }

noop: 
    atomic_dec(&dpc->nproc);
    if (find_first_bit(&dpc->bitmap, dpc->svms.num) >= dpc->svms.num && 
            atomic_cmpxchg(&dpc->nproc, 1, 0) <= 1) {
        dsm_push_cache_release(local_svm, &dpc);
        if (likely(page)) {
            unlock = trylock_page(page);
            set_page_private(page, 0);
            if (unlock)
                unlock_page(page);
            page_cache_release(page);
            if (likely(change_pte)) {
                pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
                if (likely(pte_same(*(pd.pte), pte_entry)))
                    clear_dsm_swp_entry_flag(mm,addr,pd.pte,DSM_PUSHING_BITPOS);
                pte_unmap_unlock(pd.pte, ptl);
                dsm_stats_inc(&local_svm->svm_sysfs.nb_push_success);
            }
        }
    }

    *return_pte = pd.pte;

out: 
    return active? NULL : page;
}

struct page *dsm_extract_page_from_remote(struct dsm *dsm,
        struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, unsigned long addr, u16 tag,
        pte_t **pte) {
    struct mm_struct *mm;
    struct page *page = NULL;

    BUG_ON(!local_svm);
    BUG_ON(!local_svm->priv);

    mm = local_svm->priv->mm;
    BUG_ON(!mm);

    down_read(&mm->mmap_sem);
    page = (tag == TRY_REQUEST_PAGE)?
        try_dsm_extract_page(local_svm, remote_svm, mm, addr, pte) : 
        dsm_extract_page(local_svm, remote_svm, mm, addr, pte);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    dsm_stats_inc( tag == TRY_REQUEST_PAGE?   /* keep conditions in macro */
        (page? 
            &local_svm->svm_sysfs.nb_answer_soft_pull :
            &local_svm->svm_sysfs.nb_answer_soft_pull_fail) :
        (page?
            &local_svm->svm_sysfs.nb_answer_fault :
            &local_svm->svm_sysfs.nb_answer_fault_fail));

    return page;
}
EXPORT_SYMBOL(dsm_extract_page_from_remote);

struct page *dsm_prepare_page_for_push(struct subvirtual_machine *local_svm,
        struct svm_list svms, struct mm_struct *mm, unsigned long addr,
        u32 descriptor)
{
    struct dsm_pte_data pd;
    struct dsm_page_cache *dpc;
    pte_t pte_entry, *pte;
    swp_entry_t swp_e;
    struct page *page = NULL;
    spinlock_t *ptl;
    int i = 0;

    BUG_ON(!local_svm);

retry:
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    if (unlikely(!pte_present(pte_entry))) {
        if (!pte_none(pte_entry)) {
            BUG_ON(pte_file(pte_entry));
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e) && is_migration_entry(swp_e)) {
                migration_entry_wait(mm, pd.pmd, addr);
                goto retry;
            }
        }
        /*
         * Cannot swap-out: page isn't here
         */
        goto out;
    }

    pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*pte, pte_entry))) {
        pte_unmap_unlock(pte, ptl);
        goto retry;
    }

    BUG_ON(!pte);
    page = vm_normal_page(pd.vma, addr, *pte);
    if (!page) {
        // DSM3: follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf
        if (pte_pfn(*pte) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;
        page = pte_page(*pte);
    }

    if (unlikely(PageTransHuge(page) && !PageHuge(page) && PageAnon(page))) {
        if (unlikely(split_huge_page(page)))
            goto bad_page;
    }

    if (unlikely(PageKsm(page))) {
        BUG_ON(!pd.vma);
        if (ksm_madvise(pd.vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE,
                &pd.vma->vm_flags))
            goto bad_page;
    }

    /*
     * TODO: This is used for debugging; after deprecating the syscall for PUSH
     * we can discard the next line, and replace with:
     *   BUG_ON(test_bit(PG_locked, &page->flags))
     *
     * --> native swap: we arrive with page locked from lru funcs
     * --> ioctl (debugging): we need to lock the page ourselves
     */
    if (trylock_page(page))
        i = 1;

    dpc = dsm_push_cache_add(local_svm, addr, svms, svms.num, descriptor);
    if (unlikely(!dpc))
        goto bad_page;

    dpc->pages[0] = page;
    page_cache_get(page);
    page_cache_get(page);  /* Intentionally duplicate */
    set_page_private(page, ULONG_MAX);

    /*
     * TODO: This is also used for debugging only. Remove along with the
     * trylock_page statement.
     */
    if (i)
        unlock_page(page);

    pte_unmap_unlock(pte, ptl);
    return page;
    
bad_page: 
    pte_unmap_unlock(pte, ptl);
out: 
    return NULL;
}
EXPORT_SYMBOL(dsm_prepare_page_for_push);

int dsm_cancel_page_push(struct subvirtual_machine *svm, unsigned long addr,
        struct page *page)
{
    struct dsm_page_cache *dpc = dsm_push_cache_get(svm, addr, NULL);
    int i = 0;

    if (unlikely(!dpc))
        return -1;

    dsm_push_cache_release(svm, &dpc);

    /*
     * TODO: debugging, see comment above.
     */
    if (trylock_page(page))
        i = 1;

    page_cache_release(page);
    page_cache_release(page);  /* Intentionally duplicate */
    set_page_private(page, 0);

    /*
     * TODO: debugging
     */
    if (i)
        unlock_page(page);

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
                    swp_entry_to_pte( dsm_descriptor_to_swp_entry(svm->descriptor, 0)));
        } else {
            swp_e = pte_to_swp_entry(pte_entry);
            if (!non_swap_entry(swp_e)) {
                if (is_dsm_entry(swp_e)) {
                    // store old dest
                    struct dsm_swp_data old = swp_entry_to_dsm_data(
                            pte_to_swp_entry(pte_entry));

                    if (old.dsm->dsm_id != dsm->dsm_id && old.svms.pp[0]->svm_id != svm_id) {
                        // update pte
                        set_pte_at(mm, msg->req_addr, pte,
                                swp_entry_to_pte( dsm_descriptor_to_swp_entry(svm->descriptor, 0)));

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

    return r;

}
EXPORT_SYMBOL(dsm_update_pte_entry);

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

    anon_vma = page_lock_anon_vma(page);
    if (!anon_vma)
        goto out;

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
        if (!mr || mr->local == LOCAL)
            continue;

        dsm_request_page_pull_op(svm->dsm, vma->vm_mm, svm, address, mr);
        dsm_stats_inc(&svm->svm_sysfs.nb_push_attempt);
        ret = 1;
        break;
    }

    page_unlock_anon_vma(anon_vma);
out:
    return ret;
}

#ifdef CONFIG_DSM_CORE
int push_back_if_remote_dsm_page(struct page *page)
{
    return _push_back_if_remote_dsm_page(page);
}

#else
int push_back_if_remote_dsm_page(struct page *page)
{
    return 0;
}
#endif
