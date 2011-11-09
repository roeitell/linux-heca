/*
 * dsm_def.h
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#ifndef DSM_DEF_H_
#define DSM_DEF_H_

#include <dsm/dsm_stats.h>

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/rwlock_types.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <asm/atomic.h>

#define RDMA_PAGE_SIZE PAGE_SIZE

#define MAX_CAP_SCQ 256
#define MAX_CAP_RCQ 1024

#define TX_BUF_ELEMENTS_NUM MAX_CAP_SCQ
#define RX_BUF_ELEMENTS_NUM MAX_CAP_RCQ

#define PAGE_POOL_SIZE (MAX_CAP_SCQ + MAX_CAP_RCQ)*2

/**
 * RDMA_INFO
 */
#define RDMA_INFO_CL 4
#define RDMA_INFO_SV 3
#define RDMA_INFO_READY_CL 2
#define RDMA_INFO_READY_SV 1
#define RDMA_INFO_NULL 0

/**
 * DSM_MESSAGE
 */

#define REQ_PROC                        0x01 // we are processing the request
#define REQ_RCV                         0x01 // we received a request from remote node
#define REQ_RCV_PROC                    0x02 // we are processing the request from remote node
#define REQ_REPLY                       0x02 // we received a reply to our request
#define debug_dsm
#ifdef debug_dsm
#define errk printk
#endif

static struct rcm *_rcm;

static inline struct rcm * get_rcm(void) {
        return _rcm;
}
static inline struct rcm ** get_pointer_rcm(void) {
        return &_rcm;
}

struct dsm_vm_id {
        u16 dsm_id;
        u8 svm_id;

};

struct swp_element {
        unsigned long addr;
        struct dsm_vm_id id;

        struct rb_node rb;

};

struct red_page {
        u64 pfn;
        struct dsm_vm_id id;
        unsigned long addr;

        struct rb_node rb;
};

static inline u32 dsm_vm_id_to_u32(struct dsm_vm_id *id) {
        u32 val = id->dsm_id;

        val = val << 8;

        val |= id->svm_id;

        return val;

}

static inline u16 u32_to_dsm_id(u32 val) {
        return val >> 8;

}

static inline u8 u32_to_vm_id(u32 val) {
        return val & 0xFF;

}

struct dsm {
        u16 dsm_id;

        struct list_head svm_ls;
        struct list_head ls;
};



typedef struct rcm {
        int node_ip;

        struct rdma_cm_id *cm_id;
        struct ib_device *dev;
        struct ib_pd *pd;
        struct ib_mr *mr;

        struct ib_cq *listen_cq;

        spinlock_t rcm_lock;

        spinlock_t route_lock;

        struct rb_root root_conn;
        struct rb_root root_route;

        struct sockaddr_in sin;

        struct list_head dsm_ls;
        struct rb_root red_page_root;

        struct workqueue_struct * dsm_wq;



} rcm;
struct rdma_info_data {

        void *send_mem;
        void *recv_mem;

        struct rdma_info *send_info;
        struct rdma_info *recv_info;
        struct rdma_info *remote_info;

        struct ib_sge recv_sge;
        struct ib_recv_wr recv_wr;
        struct ib_recv_wr *recv_bad_wr;

        struct ib_sge send_sge;
        struct ib_send_wr send_wr;
        struct ib_send_wr *send_bad_wr;
        int exchanged;
};

typedef struct page_pool_ele {

        void * page_buf;
        struct page * mem_page;
        struct list_head page_ptr;

} page_pool_ele;

typedef struct page_pool {

        int nb_full_element;

        struct list_head page_pool_list;
        struct list_head page_empty_pool_list;
        struct list_head page_release_list;
        struct list_head page_recycle_list;

        spinlock_t page_pool_list_lock;
        spinlock_t page_pool_empty_list_lock;
        spinlock_t page_release_lock;
        spinlock_t page_recycle_lock;

        struct work_struct page_release_work;

} page_pool;

typedef struct rx_buffer {
        struct rx_buf_ele * rx_buf;
        spinlock_t recv_lock;
} rx_buffer;

typedef struct tx_buffer {
        struct tx_buf_ele * tx_buf;

        struct list_head tx_free_elements_list;
        struct list_head tx_free_elements_list_reply;

        spinlock_t tx_free_elements_list_lock;
        spinlock_t tx_free_elements_list_reply_lock;

        struct completion completion_free_tx_element;

} tx_buffer;

typedef struct conn_element {
        rcm *rcm;

        int remote_node_ip;
        struct rdma_info_data rid;

        struct ib_mr *mr;
        struct ib_pd *pd;
        struct rdma_cm_id *cm_id;
        struct ib_cq *send_cq;
        struct ib_cq *recv_cq;

        struct tasklet_struct send_work;
        struct work_struct recv_work;

        struct rx_buffer rx_buffer;
        struct tx_buffer tx_buffer;

        struct page_pool page_pool;
        struct rb_node rb_node;

        struct con_element_stats stats;

} conn_element;

typedef struct rdma_info {

        u8 flag;
        u32 node_ip;
        u64 buf_msg_addr;
        u32 rkey_msg;
        u64 buf_rx_addr;
        u32 rkey_rx;
        u32 rx_buf_size;

} rdma_info;

typedef struct dsm_message {

        u32 msg_num;
        u32 offset;
        u32 dest;
        u32 src;
        u64 req_addr;
        u64 dst_addr;
        u32 rkey;
        u16 status;

} dsm_message;

/*
 * region represents local area of VM memory.
 */
struct mem_region {
        unsigned long addr;
        unsigned long sz;
        struct subvirtual_machine *svm;

        struct list_head ls;
        struct rcu_head rcu;

};

typedef struct private_data {

        struct rb_root root_swap;

        struct mm_struct *mm;

        unsigned long offset;
        struct subvirtual_machine *svm;

        struct list_head head;

} private_data;

struct subvirtual_machine {
        struct conn_element *ele;
        struct dsm_vm_id id;
        struct list_head mr_ls;
        struct list_head ls;

        private_data *priv;
        struct rcu_head rcu_head;
        struct rb_node rb_node;

};

typedef struct work_request_ele {
        conn_element *ele;

        struct ib_send_wr wr;
        struct ib_sge sg;
        struct ib_send_wr *bad_wr;

        dsm_message *dsm_msg;

} work_request_ele;

typedef struct msg_work_request {
        work_request_ele *wr_ele;
        page_pool_ele * dst_addr;

} msg_work_request;

typedef struct recv_work_req_ele {
        conn_element * ele;

        struct ib_recv_wr sq_wr;
        struct ib_recv_wr *bad_wr;
        struct ib_sge recv_sgl;

} recv_work_req_ele;

typedef struct reply_work_request {
        //The one for sending back a message
        work_request_ele *wr_ele;

        //The one for sending the page
        struct ib_send_wr wr;
        struct ib_send_wr *bad_wr;
        struct page * mem_page;
        void *page_buf;
        struct ib_sge page_sgl;

} reply_work_request;

struct tx_callback {
        unsigned long data;
        void (*func)(struct tx_buf_ele *, unsigned long);
};

typedef struct tx_buf_ele {
        int id;

        void *mem;
        dsm_message *dsm_msg;
        msg_work_request *wrk_req;
        reply_work_request *reply_work_req;
        struct list_head tx_buf_ele_ptr;

        struct tx_callback callback;

        struct tx_dsm_stats stats;

} tx_buf_ele;

typedef struct rx_buf_ele {
        int id;

        void *mem;
        dsm_message *dsm_msg;
        //The one for catching the request in the first place
        recv_work_req_ele *recv_wrk_rq_ele;

} rx_buf_ele;

struct page_request_completion {
        struct completion comp;
        struct page *page;
};

#endif /* DSM_DEF_H_ */
