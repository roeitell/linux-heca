/*
 * dsm_fop.h
 *
 *  Created on: 2 Aug 2011
 *      Author: jn
 */

#ifndef DSM_FOP_H_
#define DSM_FOP_H_

#include <dsm/dsm_op.h>

int destroy_rcm(void);

int destroy_connection(struct conn_element **, struct rcm *);

#endif /* DSM_FOP_H_ */
