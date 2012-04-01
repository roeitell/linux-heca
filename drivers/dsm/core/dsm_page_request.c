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
        unsigned long addr, struct svm_list svms, int nproc, u32 descriptor) {
    struct dsm_page_cache *dpc = NULL, *rb_dpc;
    struct rb_node **new, *parent = NULL;

    write_seqlock(&svm->push_cache_lock);
    for (new = &svm->push_cache.rb_node; *new; ) {
        rb_dpc = rb_entry(*new, struct dsm_page_cache, rb_node);
        parent = *new;
        if (addr < rb_dpc->addr)
            new = &(*new)->rb_left;
        else if (addr > rb_dpc->addr)
            new = &(*new)->rb_right;
        else
            goto out;
    }

    dpc = dsm_alloc_dpc(svm, addr, svms, nproc, descriptor);
    dpc->bitmap = (1 << nproc)-1;
    rb_link_node(&dpc->rb_node, parent, new);
    rb_insert_color(&dpc->rb_node, &svm->push_cache);

    out: write_sequnlock(&svm->push_cache_lock);
    return dpc;
}

static struct dsm_page_cache *dsm_push_cache_get(struct subvirtual_machine *svm,
        unsigned long addr) {
    struct rb_node *node;
    struct dsm_page_cache *dpc = NULL;

    /*
     * FIXME: Modify to read_seqbegin(); insert rcu_read_lock, to allow
     * freeing on remove.
     */
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
    write_sequnlock(&svm->push_cache_lock);

    return dpc;
}

static void dsm_push_cache_release(struct subvirtual_machine *svm,
        struct dsm_page_cache *dpc) {
    write_seqlock(&svm->push_cache_lock);
    rb_erase(&dpc->rb_node, &svm->push_cache);
    write_sequnlock(&svm->push_cache_lock);
}

static void dsm_extract_pte_data(struct dsm_pte_data *pd, struct mm_struct *mm,
        unsigned long addr) {

    retry:
    pd->pte = NULL;
    pd->vma = find_vma(mm, addr);
    if (unlikely(!pd->vma || pd->vma->vm_start > addr)) {
        printk("[_dsm_extract_pte] no VMA or bad VMA\n");
        goto out;
    }

    pd->pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd_present(*(pd->pgd)))) {
        printk("[_dsm_extract_pte] no pgd\n");
        goto out;
    }

    pd->pud = pud_offset(pd->pgd, addr);
    if (unlikely(!pud_present(*(pd->pud)))) {
        printk("[_dsm_extract_pte] no pud\n");
        goto out;
    }

    pd->pmd = pmd_offset(pd->pud, addr);
    if (unlikely(pmd_none(*(pd->pmd)))) {
        printk("[_dsm_extract_pte] no pmd error\n");
        /*
         * TODO: prepare_page_for_push did not originally have this line;
         * validate if needed in prepare_page_for_push flow
         */
        __pte_alloc(mm, pd->vma, pd->pmd, addr);
        goto retry;
    }
    if (unlikely(pmd_bad(*(pd->pmd)))) {
        pmd_clear_bad(pd->pmd);
        printk("[_dsm_extract_pte] bad pmd\n");
        goto out;
    }

    if (unlikely(pmd_trans_huge(*(pd->pmd)))) {
        printk("[_dsm_extract_pte] we have a huge pmd \n");
        spin_lock(&mm->page_table_lock);
        if (unlikely(pmd_trans_splitting(*(pd->pmd)))) {
            spin_unlock(&mm->page_table_lock);
            wait_split_huge_page(vma->anon_vma, pd->pmd);
        } else {
            spin_unlock(&mm->page_table_lock);
            split_huge_page_pmd(mm, pd->pmd);
        }
        goto retry;
    }

    pd->pte = pte_offset_map(pd->pmd, addr);
    out: return;
};

static struct page *dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm, 
        unsigned long addr) {
    spinlock_t *ptl;
    int r = 0, i, attempts = 0;
    struct dsm_page_cache *dpc = NULL;
    struct page *page = NULL;
    struct dsm_pte_data pd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct dsm_swp_data dsd;

    retry: dsm_extract_pte_data(&pd, mm, addr);
    if (!pd.pte)
        goto out;

    pte_entry = *(pd.pte);

    /*
     * If we'd been pushing the page, we would have received a try pull;
     * therefore, this is probably a regular page fault on another machine.
     *
     */
    if (unlikely(!pte_present(pte_entry))) {
        if (pte_none(pte_entry))
            goto chain_fault;

        else {
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e)) {
                if (is_dsm_entry(swp_e)) {
                    dpc = dsm_cache_get_hold(local_svm, addr);
                    if (dpc) {

                        /*
                         * Several situations can occur here:
                         *
                         * 1. We're pulling the page right now. We'll just have
                         *    to wait for finish. We need to make sure we're not
                         *    deadlocked: trying to pull from same machine who's
                         *    pulling from us.
                         *    Note: a deadlock between more than two machines is
                         *    harder to detect; hence the attempts counter.
                         *
                         */
                        if (dpc->tag == PULL_TAG || dpc->tag == PULL_TRY_TAG) {
                            atomic_dec(&dpc->nproc);
                            dsd = swp_entry_to_dsm_data(swp_e);
                            if (attempts++ > 10)
                                goto out;

                            for (i = 0; i < dsd.svms.num; i++) {
                                if (dsd.svms.pp[i] != remote_svm)
                                    goto retry;
                            }
                            goto out;
                        
                        /*
                         * FIXME: Change the logic here, can't have PUSH_TAG
                         * inside svm->page_cache
                         *
                         * 2. We're in midst of pushing the page somewhere. We
                         *    cancel the push operation, and answer the pull
                         *    request instead.
                         *
                         * TODO: We might have been trying to push somewhere
                         * else; need to re-set the pte.
                         *
                         *
                        } else if (dpc->tag == PUSH_TAG) {
                            page = dpc->pages[0];
                            if (page && trylock_page(page)) {
                                BUG_ON(page_mapcount(page));
                                dsm_cache_release(local_svm, addr);
                                dsm_dealloc_dpc(&dpc);
                                page_cache_release(page);
                                unlock_page(page);
                                goto out;
                            }
                            atomic_dec(&dpc->nproc);

                        *
                         * 3. Page has been brought as prefetch, and exists, 
                         *    waiting to be faulted in.
                         *
                         */
                        } else if (dpc->tag == PREFETCH_TAG) {
                            i = atomic_read(&dpc->found);
                            if (i >= 0)
                                page = dpc->pages[i];
                            atomic_dec(&dpc->nproc);
                            if (page) {
                                use_mm(mm);
                                down_read(&mm->mmap_sem);
                                get_user_pages(current, mm, addr, 1, 1, 0, 
                                        &page, NULL);
                                up_read(&mm->mmap_sem);
                                unuse_mm(mm);
                            }
                            goto out;
                        }

                        printk("[dsm_extract_page] trying to grab a page which we are currently pulling\n");
                        goto chain_fault;
                    } else {
                        printk("[dsm_extract_page] page not present or swapped out, or somewhere else, not handled yet\n");
                        BUG();
                    }
                } else if (is_migration_entry(swp_e)) {
                    migration_entry_wait(mm, pd.pmd, addr);
                    goto retry;
                }
                BUG();
            } else {
                chain_fault: get_user_pages(current, mm, addr, 1, 1, 0, &page,
                        NULL);
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

    set_pte_at(mm, addr, pd.pte, swp_entry_to_pte(
                dsm_descriptor_to_swp_entry(remote_svm->descriptor, 0)));

    page_remove_rmap(page);

    page_cache_release(page);

    dec_mm_counter(mm, MM_ANONPAGES);
// this is a page flagging without data exchange so we can free the page
    if (likely(!page_mapped(page)))
        try_to_free_swap(page);

    unlock_page(page);

    pte_unmap_unlock(pd.pte, ptl);
// if local

    out: return page;

    bad_page: pte_unmap_unlock(pd.pte, ptl);

// if local

    return NULL;
}

static struct page *try_dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr) {
    struct page *page = NULL;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct dsm_pte_data pd;
    int i;

    dsm_extract_pte_data(&pd, mm, addr);
    if (!pd.pte)
        goto out;
    pte_entry = *(pd.pte);

    dpc = dsm_push_cache_get(local_svm, addr);
    if (dpc) {
        for (i = 0; i < dpc->svms.num; i++) {
            if (dpc->svms.pp[i] == remote_svm)
                break;
        }
        if (i == dpc->svms.num)
            goto out;
        page = dpc->pages[0];

        if (test_and_clear_bit(i, &dpc->bitmap) && !dpc->bitmap) {
            page_cache_release(page);
            set_page_private(page, 0);
            dsm_push_cache_release(local_svm, dpc);
            dsm_dealloc_dpc(&dpc);
        }
    }

    if (unlikely(PageActive(page))) {
        page = NULL;

    } else if (pte_present(pte_entry)) {
        flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
        ptep_clear_flush_notify(pd.vma, addr, pd.pte);
        set_pte_at(mm, addr, pd.pte, swp_entry_to_pte(
                dsm_descriptor_to_swp_entry(dpc->tag, 0)));
        page_remove_rmap(page);
        dec_mm_counter(mm, MM_ANONPAGES);
        /*
         * TODO: Doesn't make sense here; original comment was: "this is a page
         * flagging without data exchange so we can free the page"
         */
        if (likely(!page_mapped(page)))
            try_to_free_swap(page);

    } else {
        if (pte_none(pte_entry))
            goto out;
  
        swp_e = pte_to_swp_entry(pte_entry);
        if (!non_swap_entry(swp_e) || !is_dsm_entry(swp_e))
            BUG_ON(page);
    }

    out: return page;
}

struct page *dsm_extract_page_from_remote(struct dsm *dsm,
        struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, unsigned long addr,
        u16 tag) {
    struct mm_struct *mm;
    struct page *page = NULL;

    mm = local_svm->priv->mm;
    down_read(&mm->mmap_sem);
    page = (tag == TRY_REQUEST_PAGE) ?
        try_dsm_extract_page(local_svm, remote_svm, mm, addr) :
        dsm_extract_page(local_svm, remote_svm, mm, addr);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    if (tag == TRY_REQUEST_PAGE) {
        if (page)
            atomic64_inc(&local_svm->svm_sysfs.stats.nb_page_sent);
        else
            atomic64_inc(&local_svm->svm_sysfs.stats.nb_page_pull_fail);
    } else {
        if (page)
            atomic64_inc(&local_svm->svm_sysfs.stats.nb_page_sent);
        else
            atomic64_inc(&local_svm->svm_sysfs.stats.nb_err);
    }

    return page;
}
EXPORT_SYMBOL(dsm_extract_page_from_remote);

int dsm_prepare_page_for_push(struct subvirtual_machine *local_svm,
        struct svm_list svms, struct mm_struct *mm, unsigned long addr,
        u32 descriptor)
{
    struct dsm_pte_data pd;
    struct dsm_page_cache *dpc;
    pte_t pte_entry, *pte;
    swp_entry_t swp_e;
    struct page *page = NULL;
    spinlock_t *ptl;

    retry: dsm_extract_pte_data(&pd, mm, addr);
    if (!pd.pte)
        goto out;
    pte_entry = *(pd.pte);

    if (unlikely(!pte_present(pte_entry))) {
        if (!pte_none(pte_entry)) {
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e)) {
                if (is_migration_entry(swp_e)) {
                    migration_entry_wait(mm, pd.pmd, addr);
                    goto retry;
                }
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

    page = vm_normal_page(pd.vma, addr, *pte);
    if (!page) {
        // DSM3: follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf
        if (pte_pfn(*pte) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;
        page = pte_page(*pte);
    }

    if (unlikely(PageTransHuge(page))) {
        if (!PageHuge(page) && PageAnon(page)) {
            if (unlikely(split_huge_page(page)))
                goto bad_page;
        }
    }

    if (unlikely(PageKsm(page))) {
        if (ksm_madvise(pd.vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE,
                &pd.vma->vm_flags))
            goto bad_page;
    }

    if (unlikely(!trylock_page(page)))
        goto bad_page;

    dpc = dsm_push_cache_add(local_svm, addr, svms, svms.num, descriptor);
    if (!dpc)
        goto bad_page;

    dpc->pages[0] = page;
    page_cache_get(page);
    page_cache_get(page); /* Intentionally duplicate */
    set_page_private(page, ULONG_MAX);
    unlock_page(page);
    pte_unmap_unlock(pte, ptl);
    return 0;

    bad_page: pte_unmap_unlock(pte, ptl);
    out: return 1;
}
EXPORT_SYMBOL(dsm_prepare_page_for_push);

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
            set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(
                dsm_descriptor_to_swp_entry(svm->descriptor, 0)));
        } else {
            swp_e = pte_to_swp_entry(pte_entry);
            if (!non_swap_entry(swp_e)) {
                if (is_dsm_entry(swp_e)) {
                    // store old dest
                    struct dsm_swp_data old = swp_entry_to_dsm_data(
                        pte_to_swp_entry(pte_entry));

                    if (old.dsm->dsm_id != dsm->dsm_id && 
                            old.svms.pp[0]->svm_id != svm_id) {
                        // update pte
                        set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(
                            dsm_descriptor_to_swp_entry(svm->descriptor, 0)));

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


