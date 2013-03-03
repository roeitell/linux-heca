/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#ifndef _HECA_BASE_H
#define _HECA_BASE_H

#include "struct.h"

/* module */
inline struct dsm_module_state *get_dsm_module_state(void);
struct dsm_module_state *create_dsm_module_state(void);
void destroy_dsm_module_state(void);

/* conn */
struct conn_element *search_rb_conn(int);
void insert_rb_conn(struct conn_element *);
void erase_rb_conn(struct conn_element *);

/* dsm */
struct dsm *find_dsm(u32);
void remove_dsm(struct dsm *);
int create_dsm(struct private_data *, __u32);

/* svm */
struct mm_struct *find_mm_by_pid(pid_t pid);
inline struct subvirtual_machine *find_svm(struct dsm *, u32);
inline struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *,
        struct mm_struct *);
inline struct subvirtual_machine *find_local_svm(struct mm_struct *);
int create_svm(struct hecaioc_svm *svm_info);
inline void release_svm(struct subvirtual_machine *);
void remove_svm(u32, u32);

/* mr */
struct memory_region *find_mr(struct subvirtual_machine *, u32);
struct memory_region *search_mr_by_addr(struct subvirtual_machine *,
        unsigned long);
int create_mr(struct unmap_data *udata);
int pushback_mr(struct unmap_data *udata);
int unmap_mr(struct unmap_data *udata);

/* rcm */
int create_rcm_listener(struct dsm_module_state *, unsigned long,
        unsigned short);
int destroy_rcm_listener(struct dsm_module_state *);
int init_rcm(void);
int fini_rcm(void);

#endif /* _HECA_BASE_H */

