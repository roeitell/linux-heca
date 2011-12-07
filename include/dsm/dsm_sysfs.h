/*
 * dsm_sysfs.h
 *
 *  Created on: 1 Dec 2011
 *      Author: jn
 */

#ifndef DSM_SYSFS_H_
#define DSM_SYSFS_H_

#include <linux/kobject.h>
#include  <linux/sysfs.h>

void dsm_sysf_cleanup(struct rcm *);
int dsm_sysf_setup(struct rcm *);

#endif /* DSM_SYSFS_H_ */
