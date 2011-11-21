/*
 * dsm_handlers.h
 *
 *  Created on: 11 Jul 2011
 *      Author: john
 */

#ifndef DSM_HANDLERS_H_
#define DSM_HANDLERS_H_

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>

int connection_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void listener_cq_handle(struct ib_cq *, void *);
int server_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void recv_cq_handle(struct ib_cq *, void *);
void send_cq_handle(struct ib_cq *, void *);
void dsm_cq_event_handler(struct ib_event *, void *);

void send_cq_handle_work(struct work_struct *);
void recv_cq_handle_work(struct work_struct *);

#endif /* DSM_HANDLERS_H_ */
