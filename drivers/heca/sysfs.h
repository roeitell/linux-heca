/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#ifndef _HECA_SYSFS_H
#define _HECA_SYSFS_H

#include <linux/kobject.h>
#include "struct.h"

int create_svm_sysfs_entry(struct heca_process *);
void delete_svm_sysfs_entry(struct kobject *);
int create_mr_sysfs_entry(struct heca_process *,
                struct heca_memory_region *);
void delete_mr_sysfs_entry(struct kobject *);
int create_dsm_sysfs_entry(struct heca_space *, struct heca_module_state *);
void delete_dsm_sysfs_entry(struct kobject *);
int create_connection_sysfs_entry(struct heca_connection *);
void delete_connection_sysfs_entry(struct heca_connection *);
int heca_sysfs_setup(struct heca_module_state *);
void heca_sysfs_cleanup(struct heca_module_state *);

#endif /* _HECA_SYSFS_H */

