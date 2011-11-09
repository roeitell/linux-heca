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

//void create_message(conn_element *, int);
void create_message(conn_element *, struct tx_buf_ele *, int, int);
int create_dummy_page(conn_element *, int);
void create_page_request(conn_element *, struct tx_buf_ele *, struct dsm_vm_id,
                struct dsm_vm_id, uint64_t);

void add_to_process_queue(conn_element *, tx_buf_ele *);
tx_buf_ele * try_get_next_empty_tx_ele(conn_element *);
tx_buf_ele * try_get_next_empty_tx_reply_ele(conn_element *);
tx_buf_ele * get_next_empty_tx_ele(conn_element *);
int init_tx_lists(conn_element *);

/*
 * CONNECTION FUNCTION
 */
int create_connection(rcm *, struct svm_data *);
int setup_connection(conn_element *, int);
int connect_client(struct rdma_cm_id *);
int create_qp(conn_element *);
int setup_qp(conn_element *);

/*
 * PAGE MANAGEMENT FUNCTION
 */
struct page_pool_ele * create_new_page_pool_element_from_page(conn_element *,
                struct page *);
int create_page_pool(conn_element *);
int create_new_page_pool_element(conn_element *);
page_pool_ele * get_page_ele(conn_element *);
void free_page_ele(conn_element *, page_pool_ele *);
void release_replace_page(conn_element *, struct tx_buf_ele *);
void release_replace_page_work(struct work_struct *);

/*
 * TX BUFFER FUNCTION
 */
int create_tx_buffer(conn_element *);
void init_tx_ele(tx_buf_ele *, conn_element *, int);
void init_tx_wr(tx_buf_ele *, u32, int);
void init_page_wr(reply_work_request *, u32, int);
void init_reply_wr(reply_work_request *, u64, u32, int);
void release_tx_element(conn_element *, tx_buf_ele *);
void release_tx_element_reply(conn_element *, tx_buf_ele *);

/*
 * RX BUFFER FUNCTION
 */
int create_rx_buffer(conn_element *);
void init_rx_ele(rx_buf_ele *, conn_element *);
void init_recv_wr(rx_buf_ele *, conn_element *);
int setup_recv_wr(conn_element *);
int refill_recv_wr(conn_element *, rx_buf_ele *);

/*
 * RDMA INFO FUNCTION
 */
void reg_rem_info(conn_element *);
int create_rdma_info(conn_element *);
void format_rdma_info(conn_element *);

#endif /* DSM_OP_H_ */
