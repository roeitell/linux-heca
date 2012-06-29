/*
 * DSM tracing system
 * Author : benoit.hudzia@sap.com
 */


#undef TRACE_SYSTEM
#define TRACE_SYSTEM dsm

#if !defined(DSM_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define DSM_TRACE_H_

#include <linux/tracepoint.h>



TRACE_EVENT(do_dsm_page_fault,
        TP_PROTO(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, pte_t *page_table, pmd_t *pmd, unsigned int flags, pte_t orig_pte, swp_entry_t swp_entry),
        TP_ARGS(mm, vma, address, page_table, pmd, flags, orig_pte, swp_entry),

        TP_STRUCT__entry( __field(u32 , mm ) __field(unsigned long, fault_addr)  __field(unsigned long, page_addr) __field(unsigned int, flags) ),

        TP_fast_assign( __entry->mm = mm;  __entry->fault_addr = address; __entry->page_addr = address & PAGE_MASK; __entry->flags = flags ),

        TP_printk("Do page fault called for mm %p  at addr : %p in page addr %p with flags %u ",  __entry->mm , __entry->fault_addr , __entry->page_addr, __entry->flags ));

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/dsm
#define TRACE_INCLUDE_FILE dsm_trace
#include <trace/define_trace.h>
