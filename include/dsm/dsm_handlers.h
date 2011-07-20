/*
 * dsm_handlers.h
 *
 *  Created on: 11 Jul 2011
 *      Author: john
 */

#ifndef DSM_HANDLERS_H_
#define DSM_HANDLERS_H_

int connection_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void listener_cq_handle(struct ib_cq *, void *);
int rcm_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void recv_cq_handle(struct ib_cq *, void *);
void send_cq_handle(struct ib_cq *, void *);

#endif /* DSM_HANDLERS_H_ */
