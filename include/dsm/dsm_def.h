/*
 * dsm_def.h
 *
 *  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#ifndef DSM_DEF_H_
#define DSM_DEF_H_

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
#include <linux/swap.h>
#include <linux/swapops.h>
#include <asm/atomic.h>

//#define ULONG_MAX       0xFFFFFFFFFFFFFFFF

#define RDMA_PAGE_SIZE PAGE_SIZE

#define MAX_CAP_SCQ 256
#define MAX_CAP_RCQ 1024

#define TX_BUF_ELEMENTS_NUM MAX_CAP_SCQ
#define RX_BUF_ELEMENTS_NUM MAX_CAP_RCQ

#define PAGE_POOL_SIZE (MAX_CAP_SCQ + MAX_CAP_RCQ)*2

#define MAX_CONSECUTIVE_SVM_FAILURES 5

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

#define REQUEST_PAGE                    0x0000 // We Request a page
#define REQUEST_PAGE_PULL               0x0001 // We Request a page pull
#define PAGE_REQUEST_REPLY              0x0002 // We Reply to a page request
#define PAGE_REQUEST_REDIRECT           0x0004 // We don't have the page  but we know where it is , we redirect
#define PAGE_INFO_UPDATE                0x0008 // We send an update of the page location
#define TRY_REQUEST_PAGE                0x0010 // We try to pull the page
#define TRY_REQUEST_PAGE_FAIL           0x0020 // We try to get the page failed
#define SVM_STATUS_UPDATE               0x0030 // The svm is down
#define DSM_MSG_ERR                     0x8000 // ERROR

/*
 * DSM DATA structure
 */

struct msg_stats {
    atomic64_t request_page;
    atomic64_t request_page_pull;
    atomic64_t page_request_reply;
    atomic64_t page_info_update;
    atomic64_t page_request_redirect;
    atomic64_t try_request_page;
    atomic64_t try_request_page_fail;
    atomic64_t err;
};

struct con_element_sysfs {
    struct kobject connection_kobject;
    struct kobject connection_rx_kobject;
    struct kobject connection_tx_kobject;
    struct msg_stats rx_stats;
    struct msg_stats tx_stats;
};

struct dsm_page_stats {
    atomic64_t nb_page_requested;
    atomic64_t nb_page_request_success;
    atomic64_t nb_page_sent;
    atomic64_t nb_page_pull;
    atomic64_t nb_page_pull_fail;
    atomic64_t nb_page_push_request;
    atomic64_t nb_page_redirect;
    atomic64_t nb_page_requested_prefetch;
    atomic64_t nb_err;
};

struct svm_sysfs {

    struct kobject svm_kobject;
    struct kobject local;
    struct dsm_page_stats stats;

};

struct dsm {
    u32 dsm_id;

    struct radix_tree_root svm_tree_root;
    struct radix_tree_root svm_mm_tree_root;
    struct rb_root mr_tree_root;

    struct mutex dsm_mutex;
    struct list_head svm_list;
    seqlock_t mr_seq_lock;

    struct list_head dsm_ptr;

    struct kobject dsm_kobject;
    int nb_local_svm;
};

struct dsm_kobjects {
    struct kobject * dsm_kobject;
    struct kobject * rdma_kobject;
    struct kobject * domains_kobject;
};

struct rcm {
    int node_ip;

    struct rdma_cm_id *cm_id;
    struct ib_device *dev;
    struct ib_pd *pd;
    struct ib_mr *mr;

    struct ib_cq *listen_cq;

    struct mutex rcm_mutex;

    struct rb_root root_conn;

    struct sockaddr_in sin;

};

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

struct page_pool_ele {

    void * page_buf;
    struct page * mem_page;
    struct list_head page_ptr;

};

struct page_pool {

    struct list_head page_empty_pool_list;
    struct list_head page_release_list;

    spinlock_t page_pool_empty_list_lock;
    spinlock_t page_release_lock;

    struct work_struct page_release_work;

};

struct rx_buffer {
    struct rx_buf_ele * rx_buf;
};

struct tx_buffer {
    struct tx_buf_ele * tx_buf;

    struct list_head tx_free_elements_list;
    struct list_head tx_free_elements_list_reply;
    struct list_head request_queue;
    spinlock_t request_queue_lock;
    spinlock_t tx_free_elements_list_lock;
    spinlock_t tx_free_elements_list_reply_lock;

};

struct conn_element {
    struct rcm *rcm;
    atomic_t alive;

    int remote_node_ip;
    struct rdma_info_data rid;

    struct ib_mr *mr;
    struct ib_pd *pd;
    struct rdma_cm_id *cm_id;
    struct ib_cq *send_cq;
    struct ib_cq *recv_cq;

    struct work_struct send_work;
    struct work_struct recv_work;

    struct rx_buffer rx_buffer;
    struct tx_buffer tx_buffer;

    struct page_pool page_pool;
    struct rb_node rb_node;

    struct con_element_sysfs sysfs;

    struct completion completion;

};

struct rdma_info {

    u8 flag;
    u32 node_ip;
    u64 buf_msg_addr;
    u32 rkey_msg;
    u64 buf_rx_addr;
    u32 rkey_rx;
    u32 rx_buf_size;

};

struct dsm_message {
    u32 dsm_id;
    u32 src_id;
    u32 dest_id;

    u16 type;
    u32 offset;
    u64 req_addr;
    u64 dst_addr;
    u32 rkey;
};

/*
 * region represents local area of VM memory.
 */
struct memory_region {
    unsigned long addr;
    unsigned long sz;
    u32 descriptor;

    struct rb_node rb_node;
    struct subvirtual_machine *svm;
};

struct private_data {
    struct mm_struct *mm;
    unsigned long offset;
    struct dsm * dsm;
    struct subvirtual_machine *svm;
};

struct subvirtual_machine {
    u32 svm_id;
    atomic_t status;
#define DSM_SVM_ONLINE 0
#define DSM_SVM_OFFLINE -1

    struct dsm *dsm;
    struct conn_element *ele;
    struct private_data *priv;
    u32 descriptor;
    struct list_head svm_ptr;
    struct list_head mr_list;

    struct radix_tree_root page_cache;
    spinlock_t page_cache_spinlock;

    struct svm_sysfs svm_sysfs;
};

struct work_request_ele {
    struct conn_element *ele;

    struct ib_send_wr wr;
    struct ib_sge sg;
    struct ib_send_wr *bad_wr;

    struct dsm_message *dsm_msg;

};

struct msg_work_request {
    struct work_request_ele *wr_ele;
    struct page_pool_ele *dst_addr;
    struct dsm_page_cache *dpc;

};

struct recv_work_req_ele {
    struct conn_element * ele;

    struct ib_recv_wr sq_wr;
    struct ib_recv_wr *bad_wr;
    struct ib_sge recv_sgl;

};

struct reply_work_request {
    //The one for sending back a message
    struct work_request_ele *wr_ele;

    //The one for sending the page
    struct ib_send_wr wr;
    struct ib_send_wr *bad_wr;
    struct page * mem_page;
    void *page_buf;
    struct ib_sge page_sgl;

};

struct tx_callback {
    int (*func)(struct tx_buf_ele *);
};

struct tx_buf_ele {
    int id;
    atomic_t used;

    void *mem;
    struct dsm_message *dsm_msg;
    struct msg_work_request *wrk_req;
    struct reply_work_request *reply_work_req;
    struct list_head tx_buf_ele_ptr;

    struct tx_callback callback;
};

struct rx_buf_ele {
    int id;
    void *mem;
    struct dsm_message *dsm_msg;
    //The one for catching the request in the first place
    struct recv_work_req_ele *recv_wrk_rq_ele;
};

struct dsm_request {
    u16 type;
    struct page *page;
    struct subvirtual_machine *svm;
    struct subvirtual_machine *fault_svm;
    uint64_t addr;
    int (*func)(struct tx_buf_ele *);
    struct dsm_message dsm_msg;
    struct list_head queue;
    struct dsm_page_cache *dpc;
};

struct dsm_module_state {

    struct rcm * rcm;
    struct mutex dsm_state_mutex;
    struct radix_tree_root dsm_tree_root;
    struct list_head dsm_list;

    struct dsm_kobjects dsm_kobjects;
    struct workqueue_struct * dsm_wq;
};

struct svm_list {
    struct subvirtual_machine **pp;
    int num;
};

struct dsm_page_cache {
    struct subvirtual_machine *svm;
    unsigned long addr;
    int tag;

    struct page **pages;
    int npages;
    atomic_t found;
    atomic_t nproc;
};

/*
 * CTL info
 */
#define DSM_IO                          0xFF
#define DSM_SVM                         _IOW(DSM_IO, 0xA0, struct svm_data)
#define DSM_CONNECT                     _IOW(DSM_IO, 0xA1, struct svm_data)
#define DSM_UNMAP_RANGE                 _IOW(DSM_IO, 0xA2, struct unmap_data)
#define DSM_MR                          _IOW(DSM_IO, 0xA3, struct unmap_data)
#define PAGE_SWAP                       _IOW(DSM_IO, 0xA4, struct dsm_message)
#define UNMAP_PAGE                      _IOW(DSM_IO, 0xA5, struct unmap_data)
#define DSM_GET_STAT                    _IOW(DSM_IO, 0xA6, struct svm_data)
#define DSM_GEN_STAT                    _IOW(DSM_IO, 0xA7, struct svm_data)
#define DSM_TRY_PUSH_BACK_PAGE          _IOW(DSM_IO, 0xA8, struct unmap_data)
#define DSM_DSM                         _IOW(DSM_IO, 0xA9, struct svm_data)

struct svm_data {
    u32 dsm_id;
    u32 svm_id;
    unsigned long offset;
    char *ip;
    int port;
    int local_port;
};

struct unmap_data {
    u32 dsm_id;
    u32 *svm_ids;
    unsigned long addr;
    size_t sz;
};

struct dsm_swp_data {
    struct dsm *dsm;
    struct svm_list svms;
    u32 flags;
};

#endif /* DSM_DEF_H_ */
