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

DECLARE_EVENT_CLASS(dsm_full_template,
        TP_PROTO(int dsm_id, int svm_id, int remote_svm_id, int mr_id,
            unsigned long addr, unsigned long shared_addr, int tag),
        TP_ARGS(dsm_id, svm_id, remote_svm_id, mr_id, addr, shared_addr, tag),
        TP_STRUCT__entry( __field(int, dsm_id ) __field(int, svm_id)
            __field(int, remote_svm_id) __field(int, mr_id)
            __field(unsigned long, addr) __field(unsigned long, shared_addr)
            __field(int, tag)),
        TP_fast_assign( __entry->dsm_id = dsm_id; __entry->svm_id = svm_id;
            __entry->remote_svm_id = remote_svm_id; __entry->mr_id = mr_id;
            __entry->addr = addr; __entry->shared_addr = shared_addr;
            __entry->tag = tag),
        TP_printk("DSM(%d) SVM(%d) Remote_SVM(%d) MR(%d) Addr(%lu) "
            "Shared_Addr(%lu) Flags(%s, %s)",
            __entry->dsm_id, __entry->svm_id, __entry->remote_svm_id,
            __entry->mr_id, __entry->addr, __entry->shared_addr,
            __print_symbolic(__entry->tag, dsm_dpc_tag),
            __print_symbolic(__entry->tag, dsm_msg_type)));

#define DSM_DECLARE_EVENT_FULL(name)                                    \
    DEFINE_EVENT(dsm_full_template, name,                               \
        TP_PROTO(int dsm_id, int svm_id, int remote_svm_id, int mr_id,  \
            unsigned long addr, unsigned long shared_addr, int tag),    \
        TP_ARGS(dsm_id, svm_id, remote_svm_id, mr_id, addr, shared_addr, tag));
DSM_DECLARE_EVENT_FULL(do_dsm_page_fault_svm);
DSM_DECLARE_EVENT_FULL(dsm_cache_add_send);
DSM_DECLARE_EVENT_FULL(do_dsm_page_fault_svm_complete);
DSM_DECLARE_EVENT_FULL(dsm_get_remote_page);
DSM_DECLARE_EVENT_FULL(dsm_pull_req_complete);
DSM_DECLARE_EVENT_FULL(dsm_try_pull_req_complete_fail);
DSM_DECLARE_EVENT_FULL(process_page_request_complete);
DSM_DECLARE_EVENT_FULL(process_page_request);
DSM_DECLARE_EVENT_FULL(send_request);
DSM_DECLARE_EVENT_FULL(delayed_gup);
DSM_DECLARE_EVENT_FULL(redirect);
DSM_DECLARE_EVENT_FULL(dsm_pull_req_success);
DSM_DECLARE_EVENT_FULL(dsm_defer_gup);
DSM_DECLARE_EVENT_FULL(dsm_defer_gup_execute);

DECLARE_EVENT_CLASS(dsm_message_template,
        TP_PROTO(int dsm_id, int svm_id, int remote_svm_id, int mr_id,
            unsigned long addr, unsigned long shared_addr, int type, int tx_id),
        TP_ARGS(dsm_id, svm_id, remote_svm_id, mr_id, addr, shared_addr, type,
            tx_id),
        TP_STRUCT__entry(__field(int, dsm_id) __field(int, svm_id) 
            __field(int, remote_svm_id) __field(int, mr_id) 
            __field(unsigned long, addr) __field(unsigned long, shared_addr)
            __field(int, type) __field(int, tx_id)),
        TP_fast_assign(__entry->dsm_id = dsm_id; __entry->svm_id = svm_id;
            __entry->remote_svm_id = remote_svm_id; __entry->mr_id = mr_id;
            __entry->addr = addr; __entry->shared_addr = shared_addr;
            __entry->type = type; __entry->tx_id = tx_id),
        TP_printk("DSM(%d) Src(%d) Dest(%d) MR(%d) Addr(%lu) "
            "Shared_Addr(%lu) Flags(%s) TX(%d)", __entry->dsm_id,
            __entry->svm_id, __entry->remote_svm_id, __entry->mr_id,
            __entry->addr, __entry->shared_addr,
            __print_symbolic(__entry->type, dsm_msg_type), __entry->tx_id));

#define DSM_DECLARE_EVENT_MESSAGE(name)                                     \
    DEFINE_EVENT(dsm_message_template, name,                                \
        TP_PROTO(int dsm_id, int svm_id, int remote_svm_id, int mr_id,      \
            unsigned long addr, unsigned long shared_addr, int type,        \
            int tx_id),                                                     \
        TP_ARGS(dsm_id, svm_id, remote_svm_id, mr_id, addr, shared_addr,    \
            type, tx_id));
DSM_DECLARE_EVENT_MESSAGE(dsm_rx_msg);
DSM_DECLARE_EVENT_MESSAGE(dsm_tx_msg);
DSM_DECLARE_EVENT_MESSAGE(queued_request);

DECLARE_EVENT_CLASS(dsm_basic_template,
        TP_PROTO(int id),
        TP_ARGS(id),
        TP_STRUCT__entry(__field(int, id)),
        TP_fast_assign(__entry->id = id;),
        TP_printk(" %d", __entry->id));

#define DSM_DECLARE_EVENT_BASIC(name)                                       \
    DEFINE_EVENT(dsm_basic_template, name, TP_PROTO(int id), TP_ARGS(id));
DSM_DECLARE_EVENT_BASIC(is_congested);
DSM_DECLARE_EVENT_BASIC(free_svm);
DSM_DECLARE_EVENT_BASIC(is_deferred);
DSM_DECLARE_EVENT_BASIC(extract_pte_data_err);
DSM_DECLARE_EVENT_BASIC(get_user_pages_res);
DSM_DECLARE_EVENT_BASIC(flushing_requests);
#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/dsm
#define TRACE_INCLUDE_FILE dsm_trace
#include <trace/define_trace.h>
