/*
 * dsm_page_request.c
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#include <asm-generic/memory_model.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include "../../../mm/internal.h"
#include <linux/page-flags.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/rmap.h>

#include <dsm/dsm_core.h>
#include <dsm/dsm_ctl.h>
#include <dsm/dsm_rb.h>

#include <linux/mmu_notifier.h>

unsigned long dst_addr;

static pte_t *dsm_page_walker(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep = 0;

    pgd = pgd_offset(mm, addr);
    if (!pgd_present(*pgd))
        goto out;

    pud = pud_offset(pgd, addr);
    if (!pud_present(*pud))
        goto out;

    pmd = pmd_offset(pud, addr);
    BUG_ON(pmd_trans_huge(*pmd));
    if (!pmd_present(*pmd))
        goto out;

    ptep = pte_offset_map(pmd, addr);

out:

    return ptep;

}

//static void forward_red_page(struct mm_struct *mm, dsm_message *msg)
//{
//    pte_t *ptep;
//    pte_t pte;
//    swp_entry_t entry;
//    struct dsm_vm_id id;
//
//    printk("[*] forward_red_page\n");
//
//    ptep = dsm_page_walker(mm, msg->req_addr);
//
//    printk("[*] z\n");
//
//    pte = *ptep;
//    if (!pte_present(pte))
//    {
//        BUG_ON(pte_none(pte));
//
//        entry = pte_to_swp_entry(pte);
//
//        if (is_dsm_entry(entry))
//        {
//            dsm_entry_to_val(entry, &id.dsm_id, &id.vm_id);
//
//            msg->dest = dsm_vm_id_to_u32(&id);
//
//        }
//
//    }
//
//}

static inline void forward_blue_page(dsm_message *msg, struct swp_element *swp_ele)
{
    msg->dest = dsm_vm_id_to_u32(&swp_ele->id);

}

struct page * dsm_extract_page(struct dsm_vm_id id, struct subvirtual_machine *svm, unsigned long norm_addr)
{

    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct page *page = NULL;
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct mm_struct *mm;

    mm = svm->priv->mm;
    down_read(&mm->mmap_sem);

    printk("[dsm_extract_page] new DSM_SWP_ENTRY set to - dsm_id : %d, svm_id : %d", id.dsm_id, id.svm_id);
retry:

	printk("[dsm_extract_page] a\n");

    vma = find_vma(mm, norm_addr);
    if (!vma || vma->vm_start > norm_addr)
        goto out;

    printk("[dsm_extract_page] b\n");

	printk("[dsm_extract_page] c\n");
	pgd = pgd_offset(mm, norm_addr);
	if (!pgd_present(*pgd))
		goto out;
	printk("[dsm_extract_page] d\n");

	pud = pud_offset(pgd, norm_addr);
	if (!pud_present(*pud))
		goto out;
	printk("[dsm_extract_page] e\n");

	pmd = pmd_offset(pud, norm_addr);
	BUG_ON(pmd_trans_huge(*pmd));
	if (!pmd_present(*pmd))
		goto out;
	printk("[dsm_extract_page] f\n");

	// we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock

	pte = pte_offset_map_lock(mm, pmd, norm_addr, &ptl);
	pte_entry = *pte;

	printk("[dsm_extract_page] g\n");

	if (!pte_present(pte_entry))
	{
		printk("[dsm_extract_page] h\n");
		if (pte_none(pte_entry))
		{
			printk("[dsm_extract_page] i\n");
			set_pte_at(mm, norm_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.svm_id)));
			//DSM1 note we might do a empty send in order to save bandwidth
			//send
			goto out_pte;

		}
		else
		{
			printk("[dsm_extract_page] j\n");
			swp_entry_t swp_e = pte_to_swp_entry(pte_entry);
			if (non_swap_entry(swp_e))
			{
				printk("[dsm_extract_page] k\n");
				if (is_dsm_entry(swp_e))
				{
					printk("[dsm_extract_page] l\n");

					// we forward the request but here we just chain fault
					// forward page red or blue
					//forward_blue_page(msg, ele);
					//goto out_pte;
					printk("[[EXTRACT_PAGE]] we chain fault on dsm entry \n");
					goto chain_fault;

				}
				else
					if (is_migration_entry(swp_e))
					{
						pte_unmap_unlock(pte, ptl);

						migration_entry_wait(mm, pmd, norm_addr);
						goto retry;
					}
					else
					{
						BUG();
					}
			}
			else
			{
				chain_fault: printk("[[EXTRACT_PAGE]] mm  faulting because swap\n");
				pte_unmap_unlock(pte, ptl);

				r = handle_mm_fault(mm, vma, norm_addr, FAULT_FLAG_WRITE);
				if (r & VM_FAULT_ERROR)
				{
					printk("[*] failed at faulting \n");
					BUG();
				}
				printk("[EXTRACT_PAGE] faulting success \n");
				r = 0;
				goto retry;

			}

		}

	}
	else
	{
		printk("[extract_page] vm_normal_page\n");
		page = vm_normal_page(vma, norm_addr, *pte);
		if (!page)
			BUG();

	}

    printk("[dsm_extract_page] m\n");

	printk("[extract_page] try_lock page\n");
    if (!trylock_page(page))
    {
        printk("[[EXTRACT_PAGE]] cannot lock page\n");
        r = -EFAULT;
        goto out_pte;
    }

    printk("[dsm_extract_page] n\n");

    flush_cache_page(vma, norm_addr, pte_pfn(*pte));
    ptep_clear_flush_notify(vma, norm_addr, pte);
    set_pte_at(mm, norm_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.svm_id)));
    page_remove_rmap(page);

    dec_mm_counter(mm, MM_ANONPAGES);
    //DSM1 do we need a put_page???/
    unlock_page(page);
out_pte:

    pte_unmap_unlock(pte, ptl);
    up_read(&mm->mmap_sem);
out:

	printk("[dsm_extract_page] o\n");

    return page;

}
EXPORT_SYMBOL(dsm_extract_page);

struct page *dsm_extract_page_from_remote(dsm_message *msg)
{
    struct dsm_vm_id id;
    struct subvirtual_machine *svm;
    struct page *page = NULL;
    unsigned long norm_addr;
    id.dsm_id = u32_to_dsm_id(msg->dest);
    id.svm_id = u32_to_vm_id(msg->dest);

    //we need to read lock here
    svm = funcs->_find_svm(&id);
    norm_addr = msg->req_addr + svm->priv->offset;
    BUG_ON(!svm);
    page = dsm_extract_page(id, svm, norm_addr);
    // we need to unlock here
    return page;

}
EXPORT_SYMBOL(dsm_extract_page_from_remote);

/*
 * Local node A sends a blue page to node B, the dsm_swp_entry on node A points to B.  Node C requests the page from Node A,
 * Node A forwards the request to Node B, which sends the page to Node C and sets the dsm_swp_entry to Node C.
 *
 * When Node D requests the page from Node A, the request needs to be passed along the whole chain until hitting Node C, which can
 * process the request and send the page.
 *
 * However - this function will allow the updating of PTE values along the chain.  Node C will send the update command to
 * Node A, it will update the dsm_swap_entry to point to Node C, then forward the command to each Node along the chain.
 *
 * Node D then requests the page from Node A, the request is now passed straight to Node C.  It is asynchronous, if Node A is not
 * updated on time, the next Node can still pass the request along fine - either to the next node or directly to the final.
 *
 */
int dsm_update_pte_entry(dsm_message *msg)  // DSM1 - update all code
{
    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct page *page;
    struct vm_area_struct *vma;
    struct dsm_vm_id id;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct rb_root *swp_root;
    struct subvirtual_machine *svm;
    struct swp_element *ele;
    swp_entry_t swp_e;
    struct mm_struct *mm;

    id.dsm_id = u32_to_dsm_id(msg->dest);
    id.svm_id = u32_to_vm_id(msg->dest);

    svm = funcs->_find_svm(&id);
    BUG_ON(!svm);
    mm = svm->priv->mm;
    down_read(&mm->mmap_sem);
retry:


    vma = find_vma(mm, msg->req_addr);
    if (!vma || vma->vm_start > msg->req_addr)
        goto out;

    page = follow_page(vma, msg->req_addr, FOLL_GET);
    if (!page)
    {

        printk("\n[*] No page FOUND \n");
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

        if (!pte_present(pte_entry))
        {
            if (pte_none(pte_entry))
            {
                set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.svm_id)));

            }
            else
            {
                swp_e = pte_to_swp_entry(pte_entry);
                if (non_swap_entry(swp_e))
                {
                    if (is_dsm_entry(swp_e))
                    {
                        swp_root = &svm->priv->root_swap;
                        ele = funcs->_search_rb_swap(swp_root, msg->req_addr);
                        if (ele)
                        {
                            // we requested the page already .. so lets wait until we have it and then send it .. bad performance... blaaaa

                            //DSM1 we should have something like migration  wait
                            printk("[*]no need to spin as we are requesting the page \n");

                        }
                        else
                        {

                            //DSM1 forward update
                            set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.svm_id)));

                        }

                    }
                    else
                        if (is_migration_entry(swp_e))
                        {
                            pte_unmap_unlock(pte, ptl);

                            migration_entry_wait(mm, pmd, msg->req_addr);
                            goto retry;
                        }
                        else
                        {
                            BUG();
                        }
                }
                else
                {
                    printk("[*] in swap no need to update\n");

                }

            }

        }
        else
        {
            printk("[*] bad pte \n");
            BUG();
        }
        pte_unmap_unlock(pte, ptl);
    }

out:


    up_read(&mm->mmap_sem);

    return r;

}
EXPORT_SYMBOL(dsm_update_pte_entry);

