/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 * Steve Walsh <steve.walsh@sap.com>
 */

#ifndef HECA_H_
#define HECA_H_

#include <asm/types.h>
#ifdef __KERNEL__
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif


#define MAX_HPROC_IDS 3 /*Is NULL terminated */

/* unmap_data flags */
#define UD_AUTO_UNMAP           (1 << 0)
#define UD_COPY_ON_ACCESS       (1 << 1)
#define UD_SHARED               (1 << 2)

struct hecaioc_hspace {
    __u32 hspace_id;
    struct sockaddr_in local;
};

struct hecaioc_hproc {
    __u32 hspace_id;
    __u32 hproc_id;
    struct sockaddr_in remote;
    int is_local;
    pid_t pid;
};

struct hecaioc_hmr {
    __u32 hspace_id;
    __u32 hproc_ids[MAX_HPROC_IDS];
    __u32 hmr_id;
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

#define HECAIOC_HSPACE_ADD           _IOW(HECAIOC, 0xA0, struct hecaioc_hspace)
#define HECAIOC_HSPACE_RM            _IOW(HECAIOC, 0xA1, struct hecaioc_hspace)

#define HECAIOC_HPROC_ADD            _IOW(HECAIOC, 0xB0, struct hecaioc_hproc)
#define HECAIOC_HPROC_RM             _IOW(HECAIOC, 0xB1, struct hecaioc_hproc)

#define HECAIOC_HMR_ADD              _IOW(HECAIOC, 0xC0, struct hecaioc_hmr)

#define HECAIOC_PS_PUSHBACK          _IOW(HECAIOC, 0xD0, struct hecaioc_ps)
#define HECAIOC_PS_UNMAP             _IOW(HECAIOC, 0xD1, struct hecaioc_ps)

#endif /* HECA_H_ */

