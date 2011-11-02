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
void insert_rb_conn(struct rcm *, struct conn_element *);
struct conn_element* search_rb_conn(struct rcm *, int);
void erase_rb_conn(struct rb_root *, struct conn_element*);

void red_page_insert(u64, struct dsm_vm_id *, unsigned long);
struct red_page *red_page_search(u64);
void red_page_erase(struct red_page *);




#endif /* DSM_RB_H_ */
