/*
 * dsm_op.h
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#ifndef DSM_OP_H_
#define DSM_OP_H_

#include <dsm/dsm_ctl.h>
#include <dsm/dsm_def.h>
#include <dsm/dsm_handlers.h>
#include <dsm/dsm_rb.h>
#include <dsm/dsm_fop.h>

unsigned int inet_addr(char *);

int create_rcm(rcm **, char *, int);

void create_page_request(conn_element *, struct tx_buf_ele *, struct dsm_vm_id,
                struct dsm_vm_id, uint64_t, struct page*);

tx_buf_ele * try_get_next_empty_tx_ele(conn_element *);
tx_buf_ele * try_get_next_empty_tx_reply_ele(conn_element *);

/*
 * CONNECTION FUNCTION
 */
int create_connection(rcm *, struct svm_data *);
int setup_connection(conn_element *, int);
int connect_client(struct rdma_cm_id *);

/*
 * PAGE MANAGEMENT FUNCTION
 */
struct page_pool_ele * create_new_page_pool_element_from_page(conn_element *,
                struct page *);

void release_replace_page(conn_element *, struct tx_buf_ele *);
void release_replace_page_work(struct work_struct *);

/*
 * TX BUFFER FUNCTION
 */

void release_tx_element(conn_element *, tx_buf_ele *);
void release_tx_element_reply(conn_element *, tx_buf_ele *);

/*
 * RX BUFFER FUNCTION
 */

int setup_recv_wr(conn_element *);
int refill_recv_wr(conn_element *, rx_buf_ele *);

/*
 * RDMA INFO FUNCTION
 */
void reg_rem_info(conn_element *);

#endif /* DSM_OP_H_ */
