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

void create_tx_buffer(rcm *);
void destroy_tx_buffer(rcm *);

unsigned int inet_addr(char *);

int create_connection(rcm *, connect_data *);
void destroy_connection(conn_element **);

void accept_connection(conn_element *);

int create_rcm(rcm **, init_data *);
void destroy_rcm(rcm **);

void create_rx_buffers(conn_element *);
void destroy_rx_buffers(conn_element *);

int create_qp(conn_element *);

int start_listener(rcm *, connect_data *);

void exchange_info_serverside(conn_element *);
void exchange_info_clientside(conn_element *);

int dsm_recv_msg(conn_element *, int);
int dsm_send_msg(conn_element *, int);
int dsm_send_info(conn_element *);
int dsm_recv_info(conn_element *);

void destroy_connections(rcm *rcm);

#endif /* DSM_OP_H_ */
