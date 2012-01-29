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

#include <dsm/dsm_stats.h>

//#define ULONG_MAX       0xFFFFFFFFFFFFFFFF

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

#define REQUEST_PAGE                    0x0000 // We Request a page
#define REQUEST_PAGE_PULL               0x0001 // We Request a page pull
#define PAGE_REQUEST_REPLY              0x0002 // We Reply to a page request
#define PAGE_REQUEST_REDIRECT           0x0004 // We don't have the page  but we know where it is , we redirect
#define PAGE_INFO_UPDATE                0x0008 // We send an update of the page location
#define TRY_REQUEST_PAGE                0x0010 // We try to pull the page
#define TRY_REQUEST_PAGE_FAIL           0x0020 // We try to get the page failed
#define DSM_MSG_ERR                     0x8000 // ERROR
/*
 * DSM DATA structure
 */

struct dsm {
    u32 dsm_id;

    struct radix_tree_root svm_tree_root;
    struct radix_tree_root svm_mm_tree_root;
    struct rb_root mr_tree_root;

    struct mutex dsm_mutex;
    struct list_head svm_list;
    seqlock_t mr_seq_lock;

    struct list_head dsm_ptr;

    int nb_local_svm;

    u32 **svm_combinations;
};

struct dsm_vm_id {
    u32 dsm_id;
    u32 *svm_ids;
};

struct dsm_kobjects {
    struct kobject * dsm_kobject;
    struct kobject * memory_kobject;
    struct kobject * rdma_kobject;
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

    struct completion completion_free_tx_element;

};

struct conn_element {
    struct rcm *rcm;

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

    struct con_element_stats stats;

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

    u32 offset;
    u64 dest;
    u64 src;
    u64 req_addr;
    u64 dst_addr;
    u32 rkey;
    u16 type;

};

/*
 * region represents local area of VM memory.
 */
struct memory_region {
    unsigned long addr;
    unsigned long sz;
    struct subvirtual_machine *svm;

    struct list_head ls;
    struct rb_node rb_node;

};

struct private_data {
    struct mm_struct *mm;
    unsigned long offset;
    struct dsm * dsm;
    struct subvirtual_machine *svm;

};

struct subvirtual_machine {
    struct dsm_vm_id id;
    struct conn_element *ele;
    struct private_data *priv;
    struct list_head svm_ptr;
    struct dsm * dsm;
    struct list_head mr_list;

    struct radix_tree_root page_cache;
    spinlock_t page_cache_spinlock;

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
    struct page_pool_ele * dst_addr;

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

    void (*func)(struct tx_buf_ele *);
};

struct tx_buf_ele {
    int id;

    void *mem;
    struct dsm_message *dsm_msg;
    struct msg_work_request *wrk_req;
    struct reply_work_request *reply_work_req;
    struct list_head tx_buf_ele_ptr;

    struct tx_callback callback;

    struct tx_dsm_stats stats;

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
    struct page * page;
    struct subvirtual_machine *svm;
    struct subvirtual_machine *fault_svm;
    uint64_t addr;
    void(*func)(struct tx_buf_ele *);
    struct dsm_message dsm_msg;
    struct list_head queue;
};

struct dsm_module_state {

    struct rcm * rcm;
    struct mutex dsm_state_mutex;
    struct radix_tree_root dsm_tree_root;
    struct list_head dsm_list;

    struct dsm_kobjects dsm_kobjects;
    struct workqueue_struct * dsm_wq;
};

/*
 * CTL info
 */
#define DSM_IO                          0xFF
#define DSM_SVM                         _IOW(DSM_IO, 0xA0, struct svm_data)
#define DSM_CONNECT                     _IOW(DSM_IO, 0xA1, struct svm_data)
#define DSM_UNMAP_RANGE                 _IOW(DSM_IO, 0xA2, struct unmap_data)
#define DSM_MR                          _IOW(DSM_IO, 0xA3, struct mr_data)
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

};

struct mr_data {
    u32 dsm_id;
    u32 svm_id;
    unsigned long start_addr;
    unsigned long size;

};

struct unmap_data {
    unsigned long addr;
    size_t sz;
    struct dsm_vm_id id;
};

/* dsm_vm_id<->u64 conversions */
struct dsm *find_dsm(u32 id);

static inline u32 lookup_svm_ids(u32 **combs, u32 *svm_ids) {
    int i, j;

    for (i = 0; combs[i]; i++) {
        for (j = 0; combs[i][j]; j++) {
            if (combs[i][j] != svm_ids[j]) {
                goto next;
            }
        }
        return i;
        next: continue;
    }

    /* TODO: dbl-size arr if needed */
    for (j = 0; svm_ids[j]; j++)
        ;
    combs[i] = kmalloc(sizeof(u32)*(j+1), GFP_KERNEL);
    memcpy(combs[i], svm_ids, sizeof(u32)*(j+1));
    combs[i+1] = NULL;
    return i;
};

static inline unsigned long dsm_vm_id_to_u64(u32 dsm_id, u32 *svm_ids) {
    struct dsm *dsm = find_dsm(dsm_id);
    BUG_ON(!dsm);

    return (lookup_svm_ids(dsm->svm_combinations, svm_ids) << 24) | dsm_id;
};

static inline struct dsm_vm_id u64_to_dsm_vm_id(unsigned long val) {
    struct dsm_vm_id id;
    struct dsm *dsm;

    id.dsm_id = val & 0xFFFFFF;
    dsm = find_dsm(id.dsm_id);
    BUG_ON(!dsm);

    id.svm_ids = dsm->svm_combinations[val >> 24];
    return id;
};

static inline struct dsm_vm_id swp_entry_to_dsm_vm_id(swp_entry_t entry) {
    return u64_to_dsm_vm_id(dsm_entry_to_val(entry));
};

static inline swp_entry_t dsm_vm_id_to_swp_entry(u32 dsm_id, u32 *svm_ids) {
    return val_to_dsm_entry(dsm_vm_id_to_u64(dsm_id, svm_ids));
};

static inline u32 *alloc_svm_ids(struct dsm *dsm, int n, ...)
{
    va_list ap;
    u32 *svm_ids, index;
    int i;
    
    va_start(ap, n);
    svm_ids = kmalloc(sizeof(u32)*(n+1), GFP_KERNEL);
    for (i = 0; i < n; i++) {
        svm_ids[i] = va_arg(ap, u32);
    }
    svm_ids[n] = 0;
    va_end(ap);

    index = lookup_svm_ids(dsm->svm_combinations, svm_ids);
    kfree(svm_ids);

    return dsm->svm_combinations[index];
}

#endif /* DSM_DEF_H_ */
