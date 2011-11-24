/*
 * rb.h
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#ifndef DSM_RB_H_
#define DSM_RB_H_

#include <dsm/dsm_def.h>

// DSM1: write_lock(conn/route) when erasing elements?!

// Connection element - rb tree
void insert_rb_conn(struct conn_element *);
struct conn_element* search_rb_conn(int);
void erase_rb_conn(struct rb_root *, struct conn_element*);

struct rcm * get_rcm(void);
struct rcm ** get_pointer_rcm(void);

struct subvirtual_machine *find_svm(struct dsm_vm_id *);
struct subvirtual_machine *find_local_svm(u16, struct mm_struct *);
int page_local(unsigned long, struct dsm_vm_id *, struct mm_struct *);
struct mem_region *find_mr(unsigned long, struct dsm_vm_id *);
struct mem_region *find_mr_source(unsigned long);

#endif /* DSM_RB_H_ */
