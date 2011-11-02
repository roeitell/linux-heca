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

#define DSM_IO 0xFF
#define DSM_SVM			_IOW(DSM_IO, 0xA0, struct svm_data)
#define DSM_CONNECT		_IOW(DSM_IO, 0xA1, struct svm_data)
#define DSM_UNMAP_RANGE		_IOW(DSM_IO, 0xA2, struct unmap_data)
#define DSM_MR                  _IOW(DSM_IO, 0xA3, struct mr_data)
#define PAGE_SWAP		_IOW(DSM_IO, 0xA4, struct dsm_message)
#define UNMAP_PAGE		_IOW(DSM_IO, 0xA5, struct unmap_data)
#define DSM_GET_STAT            _IOW(DSM_IO, 0xA6, struct svm_data)
#define DSM_GEN_STAT            _IOW(DSM_IO, 0xA7, struct svm_data)

struct svm_data {
        int dsm_id;
        int svm_id;
        unsigned long offset;
        char *ip;
        int port;

};

struct mr_data {
        int dsm_id;
        int svm_id;
        unsigned long start_addr;
        unsigned long size;

};

struct unmap_data {
        unsigned long addr;
        size_t sz;
        struct dsm_vm_id id;
};

struct subvirtual_machine *find_svm(struct dsm_vm_id *);
struct mem_region *find_mr(unsigned long, struct dsm_vm_id *);

#endif /* RDMA_H_ */
