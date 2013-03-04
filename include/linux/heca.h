/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 * Steve Walsh <steve.walsh@sap.com>
 */

#ifndef DSM_H_
#define DSM_H_

#include <asm/types.h>
#ifdef __KERNEL__
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

struct hecaioc_dsm {
    __u32 dsm_id;
    struct sockaddr_in local;
};

struct hecaioc_svm {
    __u32 dsm_id;
    __u32 svm_id;
    struct sockaddr_in remote;
    int is_local;
    pid_t pid;
};

#define MAX_SVM_IDS 3 /*Is NULL terminated */

/* unmap_data flags */
#define UD_AUTO_UNMAP           (1 << 0)
#define UD_COPY_ON_ACCESS       (1 << 1)

struct hecaioc_mr {
    __u32 dsm_id;
    __u32 svm_ids[MAX_SVM_IDS];
    __u32 mr_id;
    void *addr;
    size_t sz;
    __u32 flags;
};

struct hecaioc_ps {
    pid_t pid;
    void *addr;
    size_t sz;
};

#define HECAIOC                      0xFF

#define HECAIOC_DSM_INIT             _IOW(HECAIOC, 0xA0, struct hecaioc_dsm)
#define HECAIOC_DSM_FINI             _IOW(HECAIOC, 0xA1, struct hecaioc_dsm)

#define HECAIOC_SVM_ADD              _IOW(HECAIOC, 0xB0, struct hecaioc_svm)
#define HECAIOC_SVM_RM               _IOW(HECAIOC, 0xB1, struct hecaioc_svm)

#define HECAIOC_MR_ADD               _IOW(HECAIOC, 0xC0, struct hecaioc_mr)

#define HECAIOC_PS_PUSHBACK          _IOW(HECAIOC, 0xD0, struct hecaioc_ps)
#define HECAIOC_PS_UNMAP             _IOW(HECAIOC, 0xD1, struct hecaioc_ps)

#endif /* DSM_H_ */

