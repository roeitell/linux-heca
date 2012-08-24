/*
 * DSM tracing system
 * Author : benoit.hudzia@sap.com
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM dsm

#if !defined(DSM_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define DSM_TRACE_H_

#include <linux/tracepoint.h>
#include <dsm/dsm_def.h>
#include <dsm/dsm_core.h>


#define dsm_dpc_tag \
    { PULL_TAG,                 "PULL_TAG" }, \
    { PREFETCH_TAG,             "PREFETCH_TAG" },\
    { PUSH_TAG,                 "PUSH_TAG" }, \
    { PULL_TRY_TAG,             "PULL_TRY_TAG" }


DECLARE_EVENT_CLASS(dsm_page_fault_template,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(int, remote_dsm_id ) __field(int, remote_svm_id) __field(void *, page_addr) __field(int, tag) ),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->remote_dsm_id = remote_dsm_id; __entry->remote_svm_id = remote_svm_id;__entry->page_addr = (void *)address ; __entry->tag = tag ),

        TP_printk("Page Addr %p Fault DSM %d SVM %d Remote DSM %d SVM  %d with Flags %s", __entry->page_addr, __entry->dsm_id, __entry->svm_id, __entry->remote_dsm_id, __entry->remote_svm_id, __print_symbolic(__entry->tag, dsm_dpc_tag) ));

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

DEFINE_EVENT(dsm_page_fault_template, send_request,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, delayed_gup,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, flushing_requests,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, redirect,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_pull_req_success,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_defer_gup,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));

DEFINE_EVENT(dsm_page_fault_template, dsm_defer_gup_execute,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int tag ),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, tag));


#define dsm_msg_type \
    { REQUEST_PAGE,                 "REQUEST_PAGE" }, \
    { REQUEST_PAGE_PULL,            "REQUEST_PAGE_PULL" },\
    { PAGE_REQUEST_REPLY,           "PAGE_REQUEST_REPLY" }, \
    { PAGE_REQUEST_REDIRECT,        "PAGE_REQUEST_REDIRECT" },\
    { PAGE_INFO_UPDATE,             "PAGE_INFO_UPDATE" }, \
    { REQUEST_PAGE_PULL,            "REQUEST_PAGE_PULL" },\
    { TRY_REQUEST_PAGE,             "TRY_REQUEST_PAGE" }, \
    { PAGE_REQUEST_FAIL,            "PAGE_REQUEST_FAIL" },\
    { SVM_STATUS_UPDATE,            "SVM_STATUS_UPDATE" }, \
    { REQUEST_PAGE_PULL,            "REQUEST_PAGE_PULL" },\
    { ACK,                          "ACK" },\
    { DSM_MSG_ERR,                  "DSM_MSG_ERR" }

DECLARE_EVENT_CLASS(dsm_message_template,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int type, int tx_id),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, type, tx_id ),

        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id) __field(int, remote_dsm_id ) __field(int, remote_svm_id) __field(void *, page_addr) __field(int, type)  __field(int, tx_id)),

        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id; __entry->remote_dsm_id = remote_dsm_id; __entry->remote_svm_id = remote_svm_id;__entry->page_addr = (void *)address ; __entry->type = type ; __entry->tx_id = tx_id ),

        TP_printk("Page Addr %p From DSM %d SVM %d To DSM %d SVM %d MSG Type %s , TX_ID %d ", __entry->page_addr, __entry->dsm_id, __entry->svm_id, __entry->remote_dsm_id, __entry->remote_svm_id, __print_symbolic(__entry->type, dsm_msg_type),__entry->tx_id ));

DEFINE_EVENT(dsm_message_template, dsm_rx_msg,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int type, int tx_id),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, type, tx_id));

DEFINE_EVENT(dsm_message_template, dsm_tx_msg,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int type, int tx_id),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, type, tx_id));

DEFINE_EVENT(dsm_message_template, queued_request,
        TP_PROTO( int dsm_id, int svm_id,int remote_dsm_id, int remote_svm_id, unsigned long address, int type, int tx_id),
        TP_ARGS( dsm_id, svm_id, remote_dsm_id, remote_svm_id, address, type, tx_id));


DECLARE_EVENT_CLASS(dsm_basic_template,
        TP_PROTO(int id),
        TP_ARGS(id),
        TP_STRUCT__entry(__field(int, id)),
        TP_fast_assign(__entry->id = id;),
        TP_printk(" %d", __entry->id));

DEFINE_EVENT(dsm_basic_template, is_congested, TP_PROTO(int id), TP_ARGS(id));
DEFINE_EVENT(dsm_basic_template, tx_e_acquire, TP_PROTO(int id), TP_ARGS(id));
DEFINE_EVENT(dsm_basic_template, tx_e_release, TP_PROTO(int id), TP_ARGS(id));
DEFINE_EVENT(dsm_basic_template, release_svm, TP_PROTO(int id), TP_ARGS(id));
DEFINE_EVENT(dsm_basic_template, is_defered, TP_PROTO(int id), TP_ARGS(id));

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/dsm
#define TRACE_INCLUDE_FILE dsm_trace
#include <trace/define_trace.h>
