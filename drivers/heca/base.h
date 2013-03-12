/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#ifndef _HECA_BASE_H
#define _HECA_BASE_H

#include "struct.h"

/* conn */
struct conn_element *search_rb_conn(int);
void insert_rb_conn(struct conn_element *);
void erase_rb_conn(struct conn_element *);

/* dsm */
struct dsm *find_dsm(u32 dsm_id);
void remove_dsm(struct dsm *dsm);
int create_dsm(__u32 dsm_id);

/* svm */
inline struct subvirtual_machine *find_svm(struct dsm *, u32);
inline struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *,
        struct mm_struct *);
inline struct subvirtual_machine *find_local_svm_from_mm(struct mm_struct *mm);
int create_svm(struct hecaioc_svm *svm_info);
inline void release_svm(struct subvirtual_machine *);
void remove_svm(u32, u32);

/* mr */
struct memory_region *find_mr(struct subvirtual_machine *, u32);
struct memory_region *search_mr_by_addr(struct subvirtual_machine *,
        unsigned long);
int create_mr(struct hecaioc_mr *udata);

/* ps */
int pushback_ps(struct hecaioc_ps *udata);
int unmap_ps(struct hecaioc_ps *udata);

/* rcm */
int create_rcm_listener(struct dsm_module_state *, unsigned long,
        unsigned short);
int destroy_rcm_listener(struct dsm_module_state *);
int init_rcm(void);
int fini_rcm(void);

#endif /* _HECA_BASE_H */

