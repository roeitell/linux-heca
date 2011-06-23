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

#define RDMA_PAGE_SIZE 			4096
#define NBTHREADS				64
#define NB_MSG_PER_SEND_BUFF 	1000
#define NB_MSG_PER_RECV_BUFF 	1000

#define RDMAIO 0xFF

#define RDMA_CONNECT	_IOW(RDMAIO, 0xA0, unsigned long)

#endif /* RDMA_H_ */
