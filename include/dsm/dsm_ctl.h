/*
 * rdma.h
 *
 *  Created on: 22 Jun 2011
 *      Author: john
 */
#ifndef RDMA_H_
#define RDMA_H_

#include <linux/types.h>
#include <linux/ioctl.h>
#include <asm/byteorder.h>
#include <linux/byteorder/generic.h>
#include <dsm/dsm_def.h>

#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)

#define RDMAIO 0xFF
#define RDMA_INIT			_IOW(RDMAIO, 0xA0, struct init_data)
#define RDMA_LISTEN			_IO(RDMAIO, 0xA1)
#define RDMA_CONNECT		_IOW(RDMAIO, 0xA2, struct connect_data)

typedef struct init_data
{
	char *ip;
	int port;
	int id;

} init_data;

typedef struct connect_data
{
	char *ip;
	int port;

} connect_data;

typedef struct fd_data
{
	int vm_id;
} fd_data;


void qp_event_handler(struct ib_event *, void *);
void send_cq_handle(struct ib_cq *, void *);
void recv_cq_handle(struct ib_cq *, void *);

int close_connection(struct rdma_cm_id *);

#endif /* RDMA_H_ */
