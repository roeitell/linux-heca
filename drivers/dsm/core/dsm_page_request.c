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
	dst_addr = 0;

	kpage = alloc_page(GFP_KERNEL);
	if (!kpage)
		return -1;

	get_page(kpage);

	// DSM1 : temp code
	dst_addr =  (unsigned long) kmap(kpage);
	if (!dst_addr)
	{
		free_page(kpage);

		return -1;

	}

	printk("[*] dst_addr : %lu\n", dst_addr);

	memset((void *) dst_addr, 'X', PAGE_SIZE);

	printk("[*] <extract_page> req_addr : %lu\n", msg->req_addr);

	printk("[*] kpage : %10.10s\n", (char *) dst_addr);


	vma = find_vma_intersection(mm, msg->req_addr, msg->req_addr + PAGE_SIZE);

	page = follow_page(vma, msg->req_addr, FOLL_GET);

	if (!page)
		return -1;


	id.dsm_id = u32_to_dsm_id(msg->dest);
	id.vm_id = u32_to_dsm_id(msg->dest);

	swp_root = &funcs->_find_routing_element(&id)->data->root_swap;


	if (!trylock_page(page))
		return -1;


	pte = page_check_address(page, mm, msg->req_addr, &ptl, 0);
	if (!pte)
		return -EFAULT;



	if (funcs->_page_blue(msg->req_addr, &id))
	{
		printk("[*] insert_swp_ele->addr : %lu \n", msg->req_addr);
		funcs->_insert_rb_swap(swp_root, msg->req_addr);

	}
	else
	{
		ele = funcs->_search_rb_swap(swp_root, msg->req_addr);

		BUG_ON(!ele);

		funcs->_erase_rb_swap(swp_root, ele);

	}

	// page_remove_rmap - tears down all pte entries for this page
	page_remove_rmap(page);

	set_pte_at_notify(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry( (uint16_t) id.dsm_id, (uint8_t) id.vm_id)));

	update_mmu_cache(vma, msg->req_addr, pte);

	dec_mm_counter(mm, MM_ANONPAGES);

	pte_unmap_unlock(pte, ptl);

	put_page(page);

	return r;

}

static int forward_red_page(struct mm_struct *mm, dsm_message *msg)
{
	pte_t *pte;
	spinlock_t *ptl;
	swp_entry_t entry;
	struct dsm_vm_id id;
	struct page *page;

	struct vm_area_struct *vma = find_vma_intersection(mm, msg->req_addr, msg->req_addr + PAGE_SIZE);

	page = follow_page(vma, msg->req_addr, FOLL_GET);

	if (!page)
	{
		printk("[extract_page] follow_page fail.\n");

		return -1;

	}

	pte = page_check_address(page, mm, msg->req_addr, &ptl, 0);

	entry = pte_to_swp_entry(*pte);

	if (is_dsm_entry(entry))
	{  //DSM2: swp_ops test - + turn into dsm_vm_id
		dsm_entry_to_val(entry, &id.dsm_id, &id.vm_id);

		msg->dest = dsm_vm_id_to_u32(&id);

	}

	pte_unmap_unlock(pte, ptl);

	return 0;

}

static inline void forward_blue_page(dsm_message *msg, struct swp_element *swp_ele)
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
		else
			if (1)// DSM1: send buffer empty
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

	return ret;

}
EXPORT_SYMBOL(dsm_extract_page);


