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
#include <linux/llist.h>
#include <linux/dsm.h>

#define RDMA_PAGE_SIZE      PAGE_SIZE

#define IB_MAX_CAP_SCQ      256
#define IB_MAX_CAP_RCQ      1024    /* Heuristic; perhaps raise in the future */
#define IB_MAX_SEND_SGE     2
#define IB_MAX_RECV_SGE     2

#define IW_MAX_CAP_SCQ      256
#define IW_MAX_CAP_RCQ      1024    /* Heuristic; perhaps raise in the future */
#define IW_MAX_SEND_SGE     2
#define IW_MAX_RECV_SGE     2

#define MAX_SVMS_PER_PAGE   2

#define GUP_DELAY           HZ*5    /* 5 second */
#define REQUEST_FLUSH_DELAY 50       /* 50 usec delay */

/**
 * RDMA_INFO
 */
#define RDMA_INFO_CL        4
#define RDMA_INFO_SV        3
#define RDMA_INFO_READY_CL  2
#define RDMA_INFO_READY_SV  1
#define RDMA_INFO_NULL      0

/**
 * DSM_MESSAGE
 */

#define REQUEST_PAGE                    (1 << 0) // We Request a page
#define REQUEST_PAGE_PULL               (1 << 1) // We Request a page pull
#define PAGE_REQUEST_REPLY              (1 << 2) // We Reply to a page request
#define PAGE_REQUEST_REDIRECT           (1 << 3) // We don't have the page  but we know where it is , we redirect
#define PAGE_INFO_UPDATE                (1 << 4) // We send an update of the page location
#define TRY_REQUEST_PAGE                (1 << 5) // We try to pull the page
#define PAGE_REQUEST_FAIL               (1 << 6) // We Fail to answer a page pull
#define SVM_STATUS_UPDATE               (1 << 7) // The svm is down
#define DSM_MSG_ERR                     (1 << 8) // ERROR
#define ACK                             (1 << 9) // Msg Acknowledgement
/*
 * DSM DATA structure
 */

struct con_element_sysfs {
    struct kobject connection_kobject;
};

struct svm_sysfs {
    struct kobject svm_kobject;
};

struct dsm {
    u32 dsm_id;

    struct radix_tree_root svm_tree_root;
    struct radix_tree_root svm_mm_tree_root;

    struct mutex dsm_mutex;
    struct list_head svm_list;

    struct list_head dsm_ptr;

    struct kobject dsm_kobject;
    int nb_local_svm;
};

struct dsm_kobjects {
    struct kobject *dsm_glob_kobject;
    struct kobject *rdma_kobject;
    struct kobject *domains_kobject;
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
    seqlock_t conn_lock;

    struct sockaddr_in sin;
};

struct map_dma {
    dma_addr_t addr;
    u64 size;
    u64 dir;
};

struct rdma_info_data {
    struct rdma_info *send_buf;
    struct rdma_info *recv_buf;

    struct map_dma send_dma;
    struct map_dma recv_dma;
    struct rdma_info *remote_info;

    struct ib_sge recv_sge;
    struct ib_recv_wr recv_wr;
    struct ib_recv_wr *recv_bad_wr;

    struct ib_sge send_sge;
    struct ib_send_wr send_wr;
    struct ib_send_wr *send_bad_wr;
    int exchanged;
};

struct rx_buffer {
    struct rx_buf_ele *rx_buf;
    int len;
};

struct tx_buffer {
    struct tx_buf_ele *tx_buf;
    int len;

    struct llist_head tx_free_elements_list;
    struct llist_head tx_free_elements_list_reply;
    spinlock_t tx_free_elements_list_lock;
    spinlock_t tx_free_elements_list_reply_lock;

    struct llist_head request_queue;
    struct mutex  flush_mutex;
    struct list_head ordered_request_queue;
    int request_queue_sz;
    struct work_struct delayed_request_flush_work;
};

#define DSM_PAGE_POOL_SZ 1000
struct page_pool_ele {
    void *page_buf;
    struct page *mem_page;
    struct llist_node llnode;
};

struct dsm_page_pool {
    int cpu;
    struct page_pool_ele *buf[DSM_PAGE_POOL_SZ];
    int head;
    struct conn_element *ele;
    struct work_struct work;
};

struct conn_element {
    struct rcm *rcm;
    /* not 100% sur of this atomic regarding barrier*/
    atomic_t alive;

    int remote_node_ip;
    struct rdma_info_data rid;
    struct ib_qp_init_attr qp_attr;
    struct ib_mr *mr;
    struct ib_pd *pd;
    struct rdma_cm_id *cm_id;

    struct work_struct send_work;
    struct work_struct recv_work;

    struct rx_buffer rx_buffer;
    struct tx_buffer tx_buffer;

    void *page_pool;
    struct llist_head page_pool_elements;
    spinlock_t page_pool_elements_lock;

    struct rb_node rb_node;

    struct con_element_sysfs sysfs;

    struct completion completion;
    struct work_struct delayed_request_flush_work;
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
    /* hdr */
    u16 type;
    u64 req_addr;
    u64 dst_addr;
    u32 dsm_id;
    u32 mr_id;
    u32 src_id;
    u32 dest_id;
    u32 offset;
    u32 rkey;
};

struct memory_region {
    unsigned long addr;
    unsigned long sz;
    u32 descriptor;
    u32 mr_id;
    int local;
#define DSM_REMOTE_MR  0
#define DSM_LOCAL_MR   1

    struct rb_node rb_node;
};

struct private_data {
    struct dsm *dsm;
};

struct subvirtual_machine {
    u32 svm_id;
    struct dsm *dsm;
    struct conn_element *ele;
    struct mm_struct *mm;
    u32 descriptor;
    struct list_head svm_ptr;

    struct radix_tree_root page_cache;
    spinlock_t page_cache_spinlock;

    struct radix_tree_root mr_id_tree_root;
    struct rb_root mr_tree_root;
    struct memory_region *mr_cache;
    seqlock_t mr_seq_lock;

    struct rb_root push_cache;
    seqlock_t push_cache_lock;

    struct svm_sysfs svm_sysfs;

    struct llist_head delayed_faults;
    struct delayed_work delayed_gup_work;

    struct llist_head deferred_gups;
    struct work_struct deferred_gup_work;

    atomic_t refs;
};

struct work_request_ele {
    struct conn_element *ele;
    struct ib_send_wr wr;
    struct ib_sge sg;
    struct ib_send_wr *bad_wr;
    struct map_dma dsm_dma;
};

struct msg_work_request {
    struct work_request_ele *wr_ele;
    struct page_pool_ele *dst_addr;
    struct dsm_page_cache *dpc;
};

struct recv_work_req_ele {
    struct conn_element *ele;
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
    pte_t *pte;
    struct mm_struct *mm;
    unsigned long addr;

};

struct tx_callback {
    int (*func)(struct tx_buf_ele *);
};

struct tx_buf_ele {
    int id;
    struct dsm_message *dsm_buf;
    struct map_dma dsm_dma;
    struct msg_work_request *wrk_req;
    struct reply_work_request *reply_work_req;
    struct llist_node tx_buf_ele_ptr;

    struct tx_callback callback;
    atomic_t used;
    atomic_t released;
};

struct rx_buf_ele {
    int id;
    struct dsm_message *dsm_buf;
    struct map_dma dsm_dma;
    //The one for catching the request in the first place
    struct recv_work_req_ele *recv_wrk_rq_ele;
};

struct dsm_request {
    u16 type;
    u32 dsm_id;
    u32 local_svm_id;
    u32 remote_svm_id;
    u32 mr_id;
    struct page *page;
    struct page_pool_ele *ppe;
    uint64_t addr;
    int (*func)(struct tx_buf_ele *);
    struct dsm_message dsm_buf;
    struct dsm_page_cache *dpc;

    struct llist_node lnode;
    struct list_head ordered_list;
};

struct deferred_gup {
    struct dsm_message dsm_buf;
    struct subvirtual_machine *remote_svm;
    struct conn_element *origin_ele;
    struct memory_region *mr;
    struct llist_node lnode;
};


struct dsm_module_state {
    struct rcm * rcm;
    struct mutex dsm_state_mutex;
    struct radix_tree_root dsm_tree_root;
    struct radix_tree_root mm_tree_root;
    struct list_head dsm_list;

    struct dsm_kobjects dsm_kobjects;
    struct workqueue_struct * dsm_rx_wq;
    struct workqueue_struct * dsm_tx_wq;
};

struct svm_list {
    struct subvirtual_machine **pp;
    int num;
};

struct dsm_page_cache {
    struct subvirtual_machine *svm;
    unsigned long addr;
    u32 tag; /* used to diff between pull ops, and to store dsc for push ops */

    struct page *pages[MAX_SVMS_PER_PAGE];
    struct svm_list svms;
    /* memory barrier are ok with these atomic */
    atomic_t found;
    atomic_t nproc;
    int released;
    unsigned long bitmap;

    struct rb_node rb_node;
};

struct dsm_delayed_fault {
    unsigned long addr;
    struct llist_node node;
};

#define DSM_INFLIGHT            0x04
#define DSM_INFLIGHT_BITPOS     0x02
#define DSM_PUSHING             0x08
#define DSM_PUSHING_BITPOS      0x03

struct dsm_swp_data {
    struct dsm *dsm;
    struct svm_list svms;
    u32 flags;
};

#endif /* DSM_DEF_H_ */
