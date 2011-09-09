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
#define RDMA_REG_VM			_IOW(RDMAIO, 0xA0, struct r_data)
#define RDMA_CONNECT		_IOW(RDMAIO, 0xA1, struct connect_data)

#define PAGE_SWAP			_IOW(RDMAIO, 0xA2, struct dsm_message)

#define UNMAP_PAGE			_IOW(RDMAIO, 0xA3, struct unmap_data)
#define REGISTER_MR         _IOW(RDMAIO, 0xA4, struct dsm_mr)
#define FAKE_RDMA_CONNECT   _IOW(RDMAIO, 0xA5, struct r_data)







struct dsm_mr
{
    struct dsm_vm_id id;
    unsigned long start_addr;
    unsigned long size;
};

struct r_data
{
	int vm_id;
	int dsm_id;
	unsigned long offset;

};

struct connect_data
{
	char *ip;
	int port;
	int vm_id;
	int dsm_id;

};

struct unmap_data
{
	unsigned long addr;
	struct dsm_vm_id id;
};

struct route_element *find_routing_element(struct dsm_vm_id *);
int page_blue(unsigned long, struct dsm_vm_id *);


#endif /* RDMA_H_ */
