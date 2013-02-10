/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 */

#ifndef DSM_H_
#define DSM_H_

#include <asm/types.h>
#ifdef __KERNEL__
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

struct svm_data {
    __u32 dsm_id;
    __u32 svm_id;
    struct sockaddr_in server;
    int is_local;
};

#define MAX_SVM_IDS 3 /*Is NULL terminated */

struct unmap_data {
    __u32 dsm_id;
    __u32 svm_ids[MAX_SVM_IDS];
    __u32 mr_id;
    void *addr;
    size_t sz;
};

#define HECAIOC                      0xFF
#define HECAIOC_DSM_INIT             _IOW(HECAIOC, 0xA0, struct svm_data)
#define HECAIOC_SVM_ADD              _IOW(HECAIOC, 0xA1, struct svm_data)
#define HECAIOC_MR_ADD               _IOW(HECAIOC, 0xA3, struct unmap_data)
#define HECAIOC_MR_PUSHBACK          _IOW(HECAIOC, 0xB6, struct unmap_data)

#endif /* DSM_H_ */

