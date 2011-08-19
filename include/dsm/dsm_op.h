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

void create_tx_buffer(struct rcm *);
void destroy_tx_buffer(struct rcm *);

unsigned int inet_addr(char *);

int create_connection(struct rcm *, struct connect_data *);
void destroy_connection(struct conn_element **);

void accept_connection(struct conn_element *);

int create_rcm(struct rcm **,  char *, int);
void destroy_rcm(struct rcm **);

int create_rx_buffer(struct conn_element *);
void destroy_rx_buffer(struct conn_element *);

int create_qp(struct conn_element *);

int start_listener(struct rcm *, struct connect_data *);

void exchange_info_serverside(struct conn_element *);
void exchange_info_clientside(struct conn_element *);

int dsm_recv_msg(struct conn_element *, int);
int dsm_send_msg(struct conn_element *, int);
int dsm_send_info(struct conn_element *);
int dsm_recv_info(struct conn_element *);

void destroy_connections(struct rcm *);

#endif /* DSM_OP_H_ */
