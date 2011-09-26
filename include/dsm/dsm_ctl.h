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
#define DSM_IO 0xFF
#define DSM_SVM				_IOW(DSM_IO, 0xA6, struct svm_data)
#define DSM_CONNECT			_IOW(DSM_IO, 0xA7, struct svm_data)
#define DSM_UNMAP_RANGE		_IOW(DSM_IO, 0xA8, struct unmap_data)
#define RDMA_CONNECT		_IOW(RDMAIO, 0xA1, struct connect_data)
#define PAGE_SWAP			_IOW(RDMAIO, 0xA2, struct dsm_message)
#define UNMAP_PAGE			_IOW(RDMAIO, 0xA3, struct unmap_data)


struct svm_data
{
	int dsm_id;
	int vm_id;
	unsigned long offset;

    unsigned long start_addr;
    unsigned long size;

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
	size_t sz;
	struct dsm_vm_id id;
};

struct subvirtual_machine *find_svm(struct dsm_vm_id *);
//int page_blue(unsigned long, struct dsm_vm_id *);
struct mem_region *find_mr(unsigned long, struct dsm_vm_id *);


#endif /* RDMA_H_ */
