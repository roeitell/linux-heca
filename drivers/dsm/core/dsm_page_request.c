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

	//down_read(&mm->mmap_sem);
	//up_read(&mm->mmap_sem);
	ptep = pte_offset_map(pmd, addr);

	out: return ptep;

}

// Add page locking
static int extract_page(struct mm_struct *mm, dsm_message *msg)
{
	spinlock_t *ptl;
	pte_t *pte;
	int r = 0;
	struct page *page;
	struct dsm_vm_id id;
	struct vm_area_struct *vma;
	struct swp_element *ele;
	struct rb_root *swp_root;

	// DSM1 : temp code test kernel mem swap
	/******************************************/
        printk("[*] version 11");
	dst_addr = 0;

	kpage = alloc_page(GFP_KERNEL);
	if (!kpage)
		return -1;

	get_page(kpage);

	// DSM1 : temp code
	dst_addr = (unsigned long) kmap(kpage);
	if (!dst_addr)
	{
		free_page((unsigned long) kpage);

		return -1;

	}

	printk("[*] dst_addr : %lu\n", dst_addr);

	memset((void *) dst_addr, 'X', PAGE_SIZE);

	printk("[*] <extract_page> req_addr : %llu\n",(unsigned long long) msg->req_addr);

	printk("[*] kpage : %10.10s\n", (char *) dst_addr);
	/************************************************/

        id.dsm_id = u32_to_dsm_id(msg->dest);
        id.vm_id = u32_to_dsm_id(msg->dest);
        swp_root = &funcs->_find_routing_element(&id)->data->root_swap;

retry:

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, msg->req_addr);
	if (!vma || vma->vm_start > msg->req_addr)
		goto out;

	page = follow_page(vma, msg->req_addr, FOLL_GET);
	if (!page)
	{
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		swp_entry_t swap_entry;
		pte_t pte_entry;

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

		pte = pte_offset_map(pmd, msg->req_addr);
		pte_entry = *pte;
		if (!pte_present(pte_entry))
		{
			printk("[*] Directly inserting PTE  \n");
			set_pte_at(mm,msg->req_addr,pte,swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id,(uint8_t) id.vm_id)));
			if (funcs->_page_blue(msg->req_addr, &id))
			        {
			                printk("[*] insert_swp_ele->addr : %lu \n",(unsigned long) msg->req_addr);
			                funcs->_insert_rb_swap(swp_root, msg->req_addr);

			        }
			        else
			        {
			                ele = funcs->_search_rb_swap(swp_root, msg->req_addr);

			                BUG_ON(!ele);

			                funcs->_erase_rb_swap(swp_root, ele);

			        }

			goto out;
		}
		else
		{
			char b;
			up_read(&mm->mmap_sem);
			// we trigger  page fault
			printk("[*] we page fault  \n");
			if (sizeof(char) == copy_from_user(&b, msg->req_addr, sizeof(char)))
			{
				goto retry;

			}
			else
			{
				return -1;
			}
		}

	}





	if (!trylock_page(page))
	{
		r = -1;
		goto out;
	}

	pte = page_check_address(page, mm, msg->req_addr, &ptl, 0);
	if (!pte)
	{
		r = -EFAULT;
		goto out_page_lock;
	}


	if (funcs->_page_blue(msg->req_addr, &id))
	{
		printk("[*] page addresse: %lu \n",(unsigned long) page_address_in_vma(page, vma));
		printk("[*] insert_swp_ele->addr : %lu \n",(unsigned long) msg->req_addr);
		funcs->_insert_rb_swap(swp_root, msg->req_addr);

	}
	else
	{
		ele = funcs->_search_rb_swap(swp_root, msg->req_addr);

		BUG_ON(!ele);

		funcs->_erase_rb_swap(swp_root, ele);

	}

	flush_cache_page(vma, msg->req_addr, pte_pfn(*pte));

	ptep_clear_flush_notify(vma, msg->req_addr, pte);
	set_pte_at(mm,msg->req_addr,pte,swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
	// page_remove_rmap - tears down all pte entries for this page
	page_remove_rmap(page);
	//update_mmu_cache(vma, msg->req_addr, pte);

	dec_mm_counter(mm, MM_ANONPAGES);

	if (!page_mapped(page))
		try_to_free_swap(page);
	put_page(page);

	pte_unmap_unlock(pte, ptl);

	out_page_lock: unlock_page(page);
	out: up_read(&mm->mmap_sem);
	return r;

}

static void forward_red_page(struct mm_struct *mm, dsm_message *msg)
{
	pte_t *ptep;
	pte_t pte;
	swp_entry_t entry;
	struct dsm_vm_id id;

	printk("[*] forward_red_page\n");

	ptep = dsm_page_walker(mm, msg->req_addr);

	printk("[*] z\n");

	pte = *ptep;
	if (!pte_present(pte))
	{
		BUG_ON(pte_none(pte));

		entry = pte_to_swp_entry(pte);

		if (is_dsm_entry(entry))
		{
			dsm_entry_to_val(entry, &id.dsm_id, &id.vm_id);

			msg->dest = dsm_vm_id_to_u32(&id);

		}

	}

}

static inline void forward_blue_page(dsm_message *msg,
		struct swp_element *swp_ele)
{
	msg->dest = dsm_vm_id_to_u32(&swp_ele->id);

}

int dsm_extract_page(struct mm_struct *mm, dsm_message *msg)
{
	int ret = 0;
	struct rb_root *swp_root;
	struct dsm_vm_id id;
	struct swp_element *swp_ele;

	id.dsm_id = u32_to_dsm_id(msg->dest);
	id.vm_id = u32_to_vm_id(msg->dest);

	swp_root = &funcs->_find_routing_element(&id)->data->root_swap;

	swp_ele = funcs->_search_rb_swap(swp_root, msg->req_addr);

	if (funcs->_page_blue(msg->req_addr, &id))
	{
		/*
		 * If a blue page is in the swp_tree, it is stored on another node.
		 * We must forward the blue page request to the node containing what is actually a red page.
		 */
		if (swp_ele)
			forward_blue_page(msg, swp_ele);
		else if (1) // DSM1: send buffer empty
			extract_page(mm, msg);

	}
	else
	{
		/*
		 * If a red page is in the swp_tree, it is stored on this node.
		 * If not in the tree, the page is no longer local and we must forward the request.
		 */
		if (swp_ele)
			extract_page(mm, msg);
		else
			forward_red_page(mm, msg);

	}

	// DSM1 : next step of forward_red_page - the msg needs to be sent on!

	return ret;

}
EXPORT_SYMBOL(dsm_extract_page);

