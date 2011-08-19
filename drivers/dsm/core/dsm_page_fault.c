/*
 * page_fault.c
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

/*
 * Blue Page:
 * 		We get a page fault on a blue page when it has been swapped out, and therefore there
 * 		is a swp_element representing it in the swp_tree.
 *
 * 	Red Page:
 * 		Red pages are unmapped on VM start.
 */
static int request_page_insert(struct mm_struct *mm, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
	struct rb_root *swp_root;
	struct swp_element *swp_ele;
	dsm_message msg;
	struct dsm_vm_id id;

	dsm_entry_to_val(*entry, &id.dsm_id, &id.vm_id);

	printk("[*] request_page_insert \n");

	swp_root = &funcs->_find_routing_element(&id)->data->root_swap;

	swp_ele = funcs->_search_rb_swap(swp_root, addr);

	swp_ele->pmd = pmd;


//retry:


//	if (funcs->_page_blue(addr, &id))
//	{
//		/* If blue page not in swp_tree - means the page is now local */
//		//if (!swp_ele)
//		if (!swp_elex.addr)
//		{
//			printk("[request_page_insert] return vm_fault_major blue\n");
//			return VM_FAULT_MAJOR;
//		}
//
//		else
//			/* If blue page in swp_tree but already requested - ignore and loop */
//			if (swp_ele->flags == 1) // DSM1: create flags lol - 1 = IN
//				goto retry;
//
//	}
//	else
//	{
//		/* If red page is in swp_tree - then we have requested it.  If not received - ignore and loop */
//		if (swp_ele)
//		{
//			if (swp_ele->flags == 1) // DSM1: create flags - 1 = IN
//			{
//				printk("[request_page_insert] return vm_fault_major red\n");
//				return VM_FAULT_MAJOR;
//			}
//
//			else
//				goto retry;
//
//		}
//		else
//		{
//			printk("[request_page_insert] insert red\n");
//			funcs->_insert_rb_swap(swp_root, addr, pte);
//
//		}
//
//	}

	msg.req_addr = (uint64_t) addr;

	msg.dst_addr = (uint64_t) dst_addr;

	printk("[*] request_page_insert > dsm_insert_page \n");

	return dsm_insert_page(mm, &msg, &id);

}

int dsm_swap_wrapper(struct mm_struct *mm, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
	return request_page_insert(mm, addr, pte, entry, pmd, flags);

}

/*
 * Received a page via dsm_rdma. The buffer containing the page will be consumed,
 * the PTE will be nullified and the PTE of the faulting page (which initiated the request)
 * will be set to the received page.
 *
 * Blue pages will be removed from the swp_tree.  Red pages will remain with the flags set to
 * received.
 */
int dsm_insert_page(struct mm_struct *mm, dsm_message *msg, struct dsm_vm_id *id)
{
	struct page *recv_page;
	pte_t *pte;
	struct swp_element *swp_ele;
	struct rb_root *swp_root;
	unsigned long addr_fault = msg->req_addr;
	unsigned long addr_recv = msg->dst_addr;
	struct vm_area_struct *vma;
	spinlock_t *ptl;

	printk("[*]a\n");

	swp_root = &funcs->_find_routing_element(id)->data->root_swap;

	swp_ele = funcs->_search_rb_swap(swp_root, addr_fault);

	printk("[*]b\n");

	// Lock the faulting pte
	pte = pte_offset_map_lock(mm, swp_ele->pmd, addr_fault, &ptl);
	printk("[*]c\n");

	printk("[*] pte(2) : %lu\n", pte->pte);

	vma = find_vma_intersection(mm, addr_fault, addr_fault + PAGE_SIZE);
	if (!vma)
	{
		printk("[*] !NO VMA!\n");
		goto out;
	}


	printk("[*]d\n");

	printk("[*] dst_addr(2) : %lu\n", addr_recv);

	get_user_pages_fast(addr_recv, 1, 0 , &recv_page);
	//recv_page = follow_page(vma, addr_recv, FOLL_GET);
	if (!recv_page)
	{
		printk("[*] !NO RECV_PAGE!\n");
		goto out;
	}

	printk("[*]e\n");

	get_page(recv_page);

	// Address of page fault - points to received page.
	set_pte_at_notify(mm, addr_fault, pte, mk_pte(recv_page, vma->vm_page_prot));
	printk("[*]f\n");

	page_add_anon_rmap(recv_page, vma, addr_fault);
	printk("[*]g\n");
	inc_mm_counter(mm, MM_ANONPAGES);
	printk("[*]h\n");

	printk("[*]i\n");
	update_mmu_cache(vma, addr_fault, pte);
	printk("[*]j\n");


// LMAO this will cause page fault - we just effectively killed addr_recv.
//	if (funcs->_page_blue(addr_recv, id))
//		;//funcs->_erase_rb_swap(swp_root, swp_ele);
//	else
//		swp_ele->flags = 1; // DSM1 - swp_ele flags - 1 = IN/received

out:
	pte_unmap_unlock(pte, ptl);

	printk("[*]k\n");

	return VM_FAULT_MAJOR;

}
EXPORT_SYMBOL(dsm_insert_page);
