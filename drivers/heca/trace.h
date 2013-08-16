/*
 * Author : benoit.hudzia@sap.com
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hspace

#if !defined(HECA_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define HECA_TRACE_H_

#include <linux/tracepoint.h>
#include "pull.h"

#define heca_dpc_tag \
{ PULL_TAG,                 "PULL_TAG" }, \
{ PREFETCH_TAG,             "PREFETCH_TAG" }, \
{ PUSH_TAG,                 "PUSH_TAG" }, \
{ PULL_TRY_TAG,             "PULL_TRY_TAG" }, \
{ CLAIM_TAG,                "CLAIM_TAG" }, \
{ READ_TAG,                 "READ_TAG" }

#define msg_type_strings \
{ MSG_REQ_PAGE,                 "MSG_REQ_PAGE" }, \
{ MSG_REQ_PAGE_TRY,             "MSG_REQ_PAGE_TRY" }, \
{ MSG_REQ_READ,                 "MSG_REQ_READ" }, \
{ MSG_REQ_PAGE_PULL,            "MSG_REQ_PAGE_PULL" }, \
{ MSG_REQ_CLAIM,                "MSG_REQ_CLAIM" }, \
{ MSG_REQ_CLAIM_TRY,            "MSG_REQ_CLAIM_TRY" }, \
{ MSG_REQ_QUERY,                "MSG_REQ_QUERY" }, \
{ MSG_RES_PAGE,                 "MSG_RES_PAGE" }, \
{ MSG_RES_PAGE_REDIRECT,        "MSG_RES_PAGE_REDIRECT" }, \
{ MSG_RES_PAGE_FAIL,            "MSG_RES_PAGE_FAIL" }, \
{ MSG_RES_SVM_FAIL,             "MSG_RES_SVM_FAIL" }, \
{ MSG_RES_ACK,                  "MSG_RES_ACK" }, \
{ MSG_RES_ACK_FAIL,             "MSG_RES_ACK_FAIL" }, \
{ MSG_RES_QUERY,                "MSG_RES_QUERY" }

/*
 * Generic template with full info
 */
DECLARE_EVENT_CLASS(heca_generic_template,
                TP_PROTO(int hspace_id, int hproc_id, int remote_hproc_id,
                        int mr_id, unsigned long addr,
                        unsigned long shared_addr, int tag),
                TP_ARGS(hspace_id, hproc_id, remote_hproc_id, mr_id, addr,
                        shared_addr, tag),
                TP_STRUCT__entry( __field(int, hspace_id )
                        __field(int, hproc_id) __field(int, remote_hproc_id)
                        __field(int, mr_id)
                        __field(unsigned long, addr) __field(unsigned long,
                                shared_addr)
                        __field(int, tag)),
                TP_fast_assign( __entry->hspace_id = hspace_id;
                        __entry->hproc_id = hproc_id;
                        __entry->remote_hproc_id = remote_hproc_id;
                        __entry->mr_id = mr_id;
                        __entry->addr = addr;
                        __entry->shared_addr = shared_addr;
                        __entry->tag = tag),
                TP_printk("HSPACE(%d) HPROC(%d) Remote_HPROC(%d) MR(%d) Addr(%lu) "
                        "Shared_Addr(%lu) Flags(%s, %s)",
                        __entry->hspace_id, __entry->hproc_id,
                        __entry->remote_hproc_id, __entry->mr_id, __entry->addr,
                        __entry->shared_addr,
                        __print_symbolic(__entry->tag, hspace_dpc_tag),
                        __print_symbolic(__entry->tag, msg_type_strings)));

#define DSM_DECLARE_EVENT_FULL(name) \
        DEFINE_EVENT(heca_generic_template, name, \
                        TP_PROTO(int hspace_id, int hproc_id, \
                                int remote_hproc_id, int mr_id, \
                                unsigned long addr, \
                                unsigned long shared_addr, int tag), \
                        TP_ARGS(hspace_id, hproc_id, remote_hproc_id, \
                                mr_id, addr, shared_addr, tag));
DSM_DECLARE_EVENT_FULL(heca_do_page_fault);
DSM_DECLARE_EVENT_FULL(heca_cache_add_send);
DSM_DECLARE_EVENT_FULL(heca_do_page_fault_complete);
DSM_DECLARE_EVENT_FULL(heca_get_remote_page);
DSM_DECLARE_EVENT_FULL(heca_pull_req_complete);
DSM_DECLARE_EVENT_FULL(heca_try_pull_req_complete_fail);
DSM_DECLARE_EVENT_FULL(heca_process_page_request_complete);
DSM_DECLARE_EVENT_FULL(heca_process_page_request);
DSM_DECLARE_EVENT_FULL(heca_send_request);
DSM_DECLARE_EVENT_FULL(heca_delayed_initiated_fault);
DSM_DECLARE_EVENT_FULL(heca_immediate_initiated_fault);
DSM_DECLARE_EVENT_FULL(heca_redirect);
DSM_DECLARE_EVENT_FULL(heca_pull_req_success);
DSM_DECLARE_EVENT_FULL(heca_defer_gup);
DSM_DECLARE_EVENT_FULL(heca_defer_gup_execute);
DSM_DECLARE_EVENT_FULL(heca_claim_page);
DSM_DECLARE_EVENT_FULL(heca_write_fault);
DSM_DECLARE_EVENT_FULL(heca_discard_read_copy);

/*
 * Heca Related Message Events
 */
DECLARE_EVENT_CLASS(heca_message_template,
                TP_PROTO(int hspace_id, int hproc_id, int remote_hproc_id,
                        int mr_id, unsigned long addr,
                        unsigned long shared_addr, int type, int tx_id),
                TP_ARGS(hspace_id, hproc_id, remote_hproc_id, mr_id, addr,
                        shared_addr, type, tx_id),
                TP_STRUCT__entry(__field(int, hspace_id) __field(int, hproc_id)
                        __field(int, remote_hproc_id) __field(int, mr_id)
                        __field(unsigned long, addr) __field(unsigned long,
                                shared_addr)
                        __field(int, type) __field(int, tx_id)),
                TP_fast_assign(__entry->hspace_id = hspace_id;
                        __entry->hproc_id = hproc_id;
                        __entry->remote_hproc_id = remote_hproc_id;
                        __entry->mr_id = mr_id; __entry->addr = addr;
                        __entry->shared_addr = shared_addr;
                        __entry->type = type; __entry->tx_id = tx_id),
                TP_printk("HSPACE(%d) Src(%d) Dest(%d) MR(%d) Addr(%lu) "
                        "Shared_Addr(%lu) Flags(%s) TX(%d)", __entry->hspace_id,
                        __entry->hproc_id, __entry->remote_hproc_id,
                        __entry->mr_id, __entry->addr, __entry->shared_addr,
                        __print_symbolic(__entry->type, msg_type_strings),
                        __entry->tx_id));

#define DSM_DECLARE_EVENT_MESSAGE(name) \
        DEFINE_EVENT(heca_message_template, name, \
                        TP_PROTO(int hspace_id, int hproc_id, \
                                int remote_hproc_id, int mr_id, \
                                unsigned long addr, \
                                unsigned long shared_addr, int type, \
                                int tx_id), \
                        TP_ARGS(hspace_id, hproc_id, remote_hproc_id, \
                                mr_id, addr, shared_addr, type, tx_id));
DSM_DECLARE_EVENT_MESSAGE(heca_rx_msg);
DSM_DECLARE_EVENT_MESSAGE(heca_tx_msg);
DSM_DECLARE_EVENT_MESSAGE(heca_queued_request);

/*
 * Basic Heca events, minimal information
 */
DECLARE_EVENT_CLASS(heca_basic_template,
                TP_PROTO(int id),
                TP_ARGS(id),
                TP_STRUCT__entry(__field(int, id)),
                TP_fast_assign(__entry->id = id;),
                TP_printk(" %d", __entry->id));

#define DSM_DECLARE_EVENT_BASIC(name) \
        DEFINE_EVENT(heca_basic_template, name, TP_PROTO(int id), TP_ARGS(id));
DSM_DECLARE_EVENT_BASIC(heca_is_congested);
DSM_DECLARE_EVENT_BASIC(heca_free_hproc);
DSM_DECLARE_EVENT_BASIC(heca_extract_pte_data_err);
DSM_DECLARE_EVENT_BASIC(heca_deferred_fault);
DSM_DECLARE_EVENT_BASIC(heca_flushing_requests);


#endif /* HECA_TRACE_H_ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH drivers/heca
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
