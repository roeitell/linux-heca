/*
 * dsm_sr.h
 *
 *  Created on: 26 Jul 2011
 *      Author: john
 */

#ifndef DSM_SR_H_
#define DSM_SR_H_

#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <dsm/dsm_def.h>
#include <dsm/dsm_op.h>

/*
 * processing message in recv handler
 */
int process_response(conn_element *, struct tx_buf_ele *);
int rx_tx_message_transfer(conn_element *, struct rx_buf_ele *);
/*
 * Step 0 : Exchange rdma info
 */

int exchange_info(conn_element *, int);
int dsm_send_info(conn_element *);
int dsm_recv_info(conn_element *);

/*
 * Step 1 : ask to send a message
 */

int send_dsm_message(conn_element *, int, void(*)(struct tx_buf_ele *),
                unsigned long);
int request_dsm_page(conn_element *, struct dsm_vm_id, struct dsm_vm_id,
                uint64_t, struct page *, void(*)(struct tx_buf_ele *));
/*
 * Step 2 : sending message
 */
int tx_dsm_send(conn_element *, struct tx_buf_ele *);

#endif /* DSM_SR_H_ */
