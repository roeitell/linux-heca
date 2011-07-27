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

void exchange_info_clientside(conn_element *);
void exchange_info_serverside(conn_element *);
int dsm_send_msg(conn_element *, int);
int dsm_recv_msg(conn_element *, int);
int init_dsm_info(conn_element *);
int dsm_send_info(conn_element *);
int dsm_recv_info(conn_element *);

#endif /* DSM_SR_H_ */
