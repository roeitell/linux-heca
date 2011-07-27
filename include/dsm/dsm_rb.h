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
void insert_rb_conn(rcm *, conn_element *);
conn_element* search_rb_conn(rcm *, int);
void erase_rb_conn(struct rb_root *, conn_element*);

// route element - rb tree
void insert_rb_route(rcm *, route_element *);
route_element* search_rb_route(rcm *, dsm_vm_id *);
void erase_rb_route(struct rb_root *, route_element *);


#endif /* DSM_RB_H_ */
