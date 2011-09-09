/*
 * dsm_page_fault.h
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#ifndef DSM_PAGE_FAULT_H_
#define DSM_PAGE_FAULT_H_

#include <dsm/dsm_def.h>
#include <linux/swap.h>

struct swp_element {
    unsigned long addr;
    struct dsm_vm_id id;
    int flags;
    pmd_t *pmd;

    struct rb_node rb;

};

struct dsm_functions {
    struct route_element *(*_find_routing_element)(struct dsm_vm_id *); //find_routing_element;
    struct swp_element* (*_search_rb_swap)(struct rb_root *, unsigned long); //search_rb_swap;
    int (*_page_blue)(unsigned long, struct dsm_vm_id *); //page_blue;
    void (*_erase_rb_swap)(struct rb_root *, struct swp_element *); //erase_rb_swap;
    struct swp_element * (*_insert_rb_swap)(struct rb_root *, unsigned long); //insert_rb_swap;

};

// dsm_unmap
void reg_dsm_functions(struct route_element *(*_find_routing_element)(struct dsm_vm_id *), void(*_erase_rb_swap)(struct rb_root *, struct swp_element *), struct swp_element * (*_insert_rb_swap)(struct rb_root *, unsigned long), int(*_page_blue)(unsigned long, struct dsm_vm_id *), struct swp_element* (*_search_rb_swap)(struct rb_root *, unsigned long));
void dereg_dsm_functions(void);
int dsm_flag_page_remote(struct mm_struct *mm, struct dsm_vm_id id, unsigned long addr);

// dsm_page_request
int dsm_extract_page(dsm_message *);

// dsm_page_fault
int dsm_swap_wrapper(struct mm_struct *, unsigned long, pte_t *, swp_entry_t *, pmd_t *, unsigned int);
int dsm_insert_page(struct mm_struct *, dsm_message *, struct dsm_vm_id *);

extern struct dsm_functions *funcs;
extern unsigned long dst_addr;
extern struct page *kpage;

#endif /* DSM_PAGE_FAULT_H_ */
