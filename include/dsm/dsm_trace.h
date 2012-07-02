/*
 * DSM tracing system
 * Author : benoit.hudzia@sap.com
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM dsm

#if !defined(DSM_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define DSM_TRACE_H_

#include <linux/tracepoint.h>

TRACE_EVENT(dsm_swap_wrapper,
        TP_PROTO(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, pte_t *page_table, pmd_t *pmd, unsigned int flags, pte_t orig_pte, swp_entry_t swp_entry),
        TP_ARGS(mm, vma, address, page_table, pmd, flags, orig_pte, swp_entry),

        TP_STRUCT__entry( __field(void *, mm ) __field(void *, fault_addr) __field(void *, page_addr) __field(unsigned int, flags) ),

        TP_fast_assign( __entry->mm = (void *) mm; __entry->fault_addr = (void *) address; __entry->page_addr = (void *) (address & PAGE_MASK); __entry->flags = flags ),

        TP_printk("Do DSM page fault START for mm %p  at addr : %p in page addr %p with flags %u ", __entry->mm, __entry->fault_addr, __entry->page_addr, __entry->flags ));

TRACE_EVENT(do_dsm_page_fault_svm,
        TP_PROTO(int dsm_id, int svm_id, unsigned long address, int dsd_flags),
        TP_ARGS(dsm_id, svm_id, address, dsd_flags),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(void *, page_addr) __field(int, flags) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->page_addr = (void *)address ; __entry->flags = dsd_flags ),

        TP_printk("Do DSM Page Fault called from DSM %d - SVM %d  at page addr %p with dsd flags %u ", __entry->dsm_id, __entry->svm_id, __entry->page_addr, __entry->flags ));

TRACE_EVENT(do_dsm_page_fault_svm_complete,
        TP_PROTO(int dsm_id, int svm_id, unsigned long address),
        TP_ARGS(dsm_id, svm_id, address),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(void *, page_addr) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->page_addr = (void *)address ),

        TP_printk("Do DSM Page Fault Completed from DSM %d - SVM %d  at page addr %p  ", __entry->dsm_id, __entry->svm_id, __entry->page_addr));

TRACE_EVENT(dsm_get_remote_page,
        TP_PROTO(int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag,int nb_request_for_page ),
        TP_ARGS(dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag, nb_request_for_page),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(int, remote_dsm_id ) __field(int, remote_svm_id) __field(void *, page_addr) __field(int, tag) __field(int, nb_request_for_page)),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->remote_dsm_id = remote_dsm_id; __entry->remote_svm_id = remote_svm_id;__entry->page_addr = (void *)address ; __entry->tag = tag ;__entry->nb_request_for_page = nb_request_for_page ),

        TP_printk("Requesting page addr %p  for DSM %d - SVM %d from DSM %d - SVM %d with Tag %d and request nb %d  ",__entry->page_addr, __entry->dsm_id, __entry->svm_id, __entry->remote_dsm_id, __entry->remote_svm_id, __entry->tag, __entry->nb_request_for_page ));

TRACE_EVENT(dsm_pull_req_complete,
        TP_PROTO(int dsm_id, int svm_id, unsigned long address, int dpc_tag),
        TP_ARGS(dsm_id, svm_id, address, dpc_tag),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(void *, page_addr) __field(int, dpc_tag) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->page_addr = (void *)address ; __entry->dpc_tag = dpc_tag ),

        TP_printk("DSM page Pull Success for DSM %d - SVM %d  at page addr %p with dpc tag %u ", __entry->dsm_id, __entry->svm_id, __entry->page_addr, __entry->dpc_tag ));

TRACE_EVENT(dsm_try_pull_req_complete_fail,
        TP_PROTO(int dsm_id, int svm_id, unsigned long address, int dpc_tag),
        TP_ARGS(dsm_id, svm_id, address, dpc_tag),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(void *, page_addr) __field(int, dpc_tag) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->page_addr = (void *)address ; __entry->dpc_tag = dpc_tag ),

        TP_printk("DSM TRY page Pull Failure for DSM %d - SVM %d  at page addr %p with dpc tag %u ", __entry->dsm_id, __entry->svm_id, __entry->page_addr, __entry->dpc_tag ));

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/dsm
#define TRACE_INCLUDE_FILE dsm_trace
#include <trace/define_trace.h>
