/*
 * dsm_def.h
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#ifndef DSM_DEF_H_
#define DSM_DEF_H_

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/rwlock_types.h>

#define TX_BUF_ELEMENTS_NUM 1
#define RX_BUF_ELEMENTS_NUM 1
#define DSM_MESSAGE_NUM 1
#define MSG_WORK_REQUEST_NUM 1

struct dsm_vm_id {
    u16 dsm_id;
    u8 vm_id;

};

static inline u32 dsm_vm_id_to_u32(struct dsm_vm_id *id) {
    u32 val = id->dsm_id;

    val = val << 8;

    val |= id->vm_id;

    return val;

}

static inline u16 u32_to_dsm_id(u32 val) {
    return val >> 8;

}

static inline u8 u32_to_vm_id(u32 val) {
    return val & 0xFF;

}

struct rcm {
    int node_ip;

    struct rdma_cm_id *cm_id;
    struct ib_device *dev;
    struct ib_pd *pd;
    struct ib_mr *mr;

    struct ib_cq *listen_cq;

    rwlock_t conn_lock;
    rwlock_t route_lock;

    struct rb_root root_conn;
    struct rb_root root_route;

    struct sockaddr_in sin;

    struct tx_buf_ele *tx_buf;

};

struct conn_element {
    struct rcm *rcm;

    int remote_node_ip;

    struct ib_mr *mr;
    struct ib_pd *pd;

    void *send_mem;
    void *recv_mem;

    struct rdma_info *send_info;
    struct rdma_info *recv_info;

    struct ib_qp *qp;
    struct ib_cq *send_cq;
    struct ib_cq *recv_cq;
    struct rdma_cm_id *cm_id;

    struct rx_buf_ele *rx_buf;

    struct rb_node rb_node;

    struct semaphore sem;

    int phase;

};

typedef struct rdma_info {
    u16 node_ip;
    u64 buf_msg_addr;
    u32 rkey_msg;
    u64 buf_rx_addr;
    u32 rkey_rx;
    u32 rx_buf_size;

} rdma_info;

typedef struct dsm_message {
    u32 msg_type;
    u32 offset;
    u32 dest;
    u32 src;
    u64 req_addr;
    u64 dst_addr;
    u32 rkey;
    u8 status;

} dsm_message;


typedef struct dsm_data {
    struct dsm_vm_id id;

    struct rb_root root_swap;

    spinlock_t root_swap_lock;

    struct mm_struct *mm;

    // TEMPORARY
    unsigned long remote_addr;

} dsm_data;

struct route_element {
    struct conn_element *ele;
    struct dsm_vm_id id;

    dsm_data *data;

    struct rb_node rb_node;

// DSM2: function ptrs may be required here - send / request page etc etc.

};

typedef struct work_request_ele {
    struct conn_element *ele;

    struct ib_send_wr wr;
    struct ib_sge sg;
    struct ib_send_wr *bad_wr;

    dsm_message *dsm_msg;

} work_request_ele;

typedef struct msg_work_request {
    work_request_ele *wr_ele;
    void *page_buf;

} msg_work_request;

typedef struct recv_work_req_ele {
    struct ib_recv_wr sq_wr;
    struct ib_recv_wr *bad_wr;
} recv_work_req_ele;

typedef struct reply_work_request {
    //The one for sending back a message
    work_request_ele *wr_ele;

    //The one for sending the page
    struct ib_send_wr wr;
    struct ib_send_wr *bad_wr;
    void *page_buf;
    struct ib_sge page_sgl;

    //The one for catching the request in the first place
    recv_work_req_ele *recv_wrk_rq_ele;

} reply_work_request;

typedef struct tx_buf_ele {
    void *mem;
    dsm_message *dsm_msg;
    msg_work_request *wrk_req;

} tx_buf_ele;

typedef struct rx_buf_ele {
    void *mem;
    dsm_message *dsm_msg;
    reply_work_request *reply_work_req;

} rx_buf_ele;

#endif /* DSM_DEF_H_ */
