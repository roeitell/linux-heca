/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 */

#ifndef DSM_H_
#define DSM_H_

#include <asm/types.h>

#define MAX_ADDR_STR 20

struct svm_data {
    __u32 dsm_id;
    __u32 svm_id;
    unsigned long offset;
    char ip[MAX_ADDR_STR];
    int port;
    int local_port;
};

#define MAX_SVM_IDS 3

struct unmap_data {
    __u32 dsm_id;
    unsigned long addr;
    size_t sz;
    __u32 svm_ids[MAX_SVM_IDS];
};

#define DSM_IO                          0xFF
/* operation */
#define DSM_DSM                         _IOW(DSM_IO, 0xA0, struct svm_data)
#define DSM_SVM                         _IOW(DSM_IO, 0xA1, struct svm_data)
#define DSM_CONNECT                     _IOW(DSM_IO, 0xA2, struct svm_data)
#define DSM_MR                          _IOW(DSM_IO, 0xA3, struct unmap_data)
/* debug/development */
#define DSM_GET_STAT                    _IOW(DSM_IO, 0xB4, struct svm_data)
#define DSM_GEN_STAT                    _IOW(DSM_IO, 0xB5, struct svm_data)
#define DSM_TRY_PUSH_BACK_PAGE          _IOW(DSM_IO, 0xB6, struct unmap_data)

#endif /* DSM_H_ */

