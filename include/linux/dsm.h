/*
 * dsm.h
 *
 *  Created on: 7 Oct 2011
 *      Author: john
 */

#ifndef DSM_H_
#define DSM_H_

#include <linux/mm.h>

#ifdef CONFIG_DSM_CORE

static inline int PageDsm(struct page *page)
{
    return ((unsigned long) page->mapping & PAGE_MAPPING_DSM) != 0;

}

#else /* !CONFIG_DSM_CORE */

static inline int PageDsm(struct page *page)
{
    return 0;
}

#endif /* CONFIG_DSM_CORE */

#endif /* DSM_H_ */
