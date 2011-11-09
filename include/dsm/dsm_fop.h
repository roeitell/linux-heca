/*
 * dsm_fop.h
 *
 *  Created on: 2 Aug 2011
 *      Author: jn
 */

#ifndef DSM_FOP_H_
#define DSM_FOP_H_

#include <dsm/dsm_op.h>

int destroy_rcm(rcm **);
int destroy_connections(rcm *);
int destroy_connection(conn_element **, rcm *);

void destroy_tx_buffer(conn_element *);
void destroy_rx_buffer(conn_element *);

void free_stat_data(conn_element *);
void free_rdma_info(conn_element *);
void free_dummy_page(conn_element *, int);

#endif /* DSM_FOP_H_ */
