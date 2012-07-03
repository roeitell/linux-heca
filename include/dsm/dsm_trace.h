/*
 * DSM tracing system
 * Author : benoit.hudzia@sap.com
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM dsm

#if !defined(DSM_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define DSM_TRACE_H_

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(dsm_page_fault_template,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(int, remote_dsm_id ) __field(int, remote_svm_id) __field(void *, page_addr) __field(int, tag) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->remote_dsm_id = remote_dsm_id; __entry->remote_svm_id = remote_svm_id;__entry->page_addr = (void *)address ; __entry->tag = tag ),

        TP_printk(" %p | %d | %d | %d | %d | %d", __entry->page_addr, __entry->dsm_id, __entry->svm_id, __entry->remote_dsm_id, __entry->remote_svm_id, __entry->tag ));

DEFINE_EVENT(dsm_page_fault_template, do_dsm_page_fault_svm,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_cache_add_send,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, do_dsm_page_fault_svm_complete,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_get_remote_page,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_pull_req_complete,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_try_pull_req_complete_fail,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, process_page_request_complete,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, process_page_request,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/dsm
#define TRACE_INCLUDE_FILE dsm_trace
#include <trace/define_trace.h>
