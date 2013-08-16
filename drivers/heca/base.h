/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#ifndef _HECA_BASE_H
#define _HECA_BASE_H

#include "struct.h"

/* conn */
struct heca_connection *search_rb_conn(int);
void insert_rb_conn(struct heca_connection *);
void erase_rb_conn(struct heca_connection *);

/* heca space */
struct heca_space *find_hspace(u32);
void remove_hspace(struct heca_space *);
int create_hspace(__u32);

/* hproc */
inline struct heca_process *find_hproc(struct heca_space *, u32);
inline struct heca_process *find_local_hproc_in_hspace(struct heca_space *,
                struct mm_struct *);
inline struct heca_process *find_local_hproc_from_mm(struct mm_struct *);
int create_hproc(struct hecaioc_hproc *);
inline void release_hproc(struct heca_process *);
void remove_hproc(u32, u32);
struct heca_process *find_any_hproc(struct heca_space *,
                struct heca_process_list);

/* mr */
struct heca_memory_region *find_heca_mr(struct heca_process *, u32);
struct heca_memory_region *search_heca_mr_by_addr(struct heca_process *,
                unsigned long);
int create_heca_mr(struct hecaioc_hmr *udata);

/* ps */
int pushback_ps(struct hecaioc_ps *udata);
int unmap_ps(struct hecaioc_ps *udata);

/* hcm */
int create_hcm_listener(struct heca_module_state *, unsigned long,
                unsigned short);
int destroy_hcm_listener(struct heca_module_state *);
int init_hcm(void);
int fini_hcm(void);

#endif /* _HECA_BASE_H */

