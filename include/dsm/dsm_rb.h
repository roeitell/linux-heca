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

// route element - rb tree
void insert_rb_route(struct rcm *, struct route_element *);
struct route_element* search_rb_route(struct rcm *, struct dsm_vm_id *);
void erase_rb_route(struct rb_root *, struct route_element *);

/*
 *  page swap RB_TREE
 */
int insert_rb_swap(struct rb_root *, unsigned long);
struct swp_element* search_rb_swap(struct rb_root *, unsigned long);
void erase_rb_swap(struct rb_root *, struct swp_element *);

#endif /* DSM_RB_H_ */
