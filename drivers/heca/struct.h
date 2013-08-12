/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 */

#ifndef HECA_STRUCT_H_
#define HECA_STRUCT_H_

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
#include <linux/heca.h>

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
#define REQUEST_FLUSH_DELAY 50      /* 50 usec delay */

/*
 * RDMA_INFO
*/
#define RDMA_INFO_CL        4
#define RDMA_INFO_SV        3
#define RDMA_INFO_READY_CL  2
#define RDMA_INFO_READY_SV  1
#define RDMA_INFO_NULL      0

/*
 * HECA Messages
 */
#define MSG_REQ_PAGE                (1 << 0)
#define MSG_REQ_PAGE_TRY            (1 << 1)
#define MSG_REQ_READ                (1 << 2)
#define MSG_REQ_PAGE_PULL           (1 << 3)
#define MSG_REQ_CLAIM               (1 << 4)
#define MSG_REQ_CLAIM_TRY           (1 << 5)
#define MSG_REQ_QUERY               (1 << 6)
#define MSG_RES_PAGE                (1 << 7)
#define MSG_RES_PAGE_REDIRECT       (1 << 8)
#define MSG_RES_PAGE_FAIL           (1 << 9)
#define MSG_RES_SVM_FAIL            (1 << 10)
#define MSG_RES_ACK                 (1 << 11)
#define MSG_RES_ACK_FAIL            (1 << 12)
#define MSG_RES_QUERY               (1 << 13)

/*
 * MEMORY REGION FLAGS
 */
#define MR_LOCAL                (1 << 0)
#define MR_COPY_ON_ACCESS       (1 << 1)
#define MR_SHARED               (1 << 2)

/*
 * Heca Space Page Pool Size
 * 1000 * 4 KB ~= 4 MB
 */
#define HSPACE_PAGE_POOL_SZ 1000

/*
 * DSM DATA structure
 */
struct heca_space {
        u32 hspace_id;

        struct radix_tree_root hprocs_tree_root;
        struct radix_tree_root hprocs_mm_tree_root;

        struct mutex hspace_mutex;
        struct list_head hprocs_list;

        struct list_head hspace_ptr;

        struct kobject hspace_kobject;
        int nb_local_hprocs;
};

struct heca_space_kobjects {
        struct kobject *hspace_glob_kobject;
        struct kobject *rdma_kobject;
        struct kobject *domains_kobject;
};

struct heca_connections_manager {
        int node_ip;

        struct rdma_cm_id *cm_id;
        struct ib_device *dev;
        struct ib_pd *pd;
        struct ib_mr *mr;

        struct ib_cq *listen_cq;

        struct mutex hcm_mutex;

        struct rb_root connections_rb_tree_root;
        seqlock_t connections_lock;

        struct sockaddr_in sin;
};

struct map_dma {
        dma_addr_t addr;
        u64 size;
        u64 dir;
};

struct rdma_info_data {
        struct heca_rdma_info *send_buf;
        struct heca_rdma_info *recv_buf;

        struct map_dma send_dma;
        struct map_dma recv_dma;
        struct heca_rdma_info *remote_info;

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


struct heca_page_pool_element {
        void *page_buf;
        struct page *mem_page;
        struct llist_node llnode;
};

struct heca_space_page_pool {
        int cpu;
        struct heca_page_pool_element *hspace_page_pool[HSPACE_PAGE_POOL_SZ];
        int head;
        struct heca_connection_element *connection;
        struct work_struct work;
};

struct heca_connection_element {
        struct heca_connections_manager *hcm;
        /* not 100% sure of this atomic regarding barrier*/
        atomic_t alive;

        struct sockaddr_in local, remote;
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

        struct kobject kobj;

        struct completion completion;
        struct work_struct delayed_request_flush_work;
};

struct heca_rdma_info {

        u8 flag;
        u32 node_ip;
        u64 buf_msg_addr;
        u32 rkey_msg;
        u64 buf_rx_addr;
        u32 rkey_rx;
        u32 rx_buf_size;
};

struct heca_message {
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

struct heca_memory_region {
        unsigned long addr;
        unsigned long sz;
        u32 descriptor;
        u32 hmr_id;
        u32 flags;
        struct rb_node rb_node;
        struct kobject hmr_kobject;
};

struct heca_process {
        u32 hproc_id;
        int is_local;
        struct heca_space *hspace;
        struct heca_connection_element *connection;
        pid_t pid;
        struct mm_struct *mm;
        u32 descriptor;
        struct list_head hproc_ptr;

        struct radix_tree_root page_cache;
        spinlock_t page_cache_spinlock;

        struct radix_tree_root page_readers;
        spinlock_t page_readers_spinlock;

        struct radix_tree_root page_maintainers;
        spinlock_t page_maintainers_spinlock;

        struct radix_tree_root hmr_id_tree_root;
        struct rb_root hmr_tree_root;
        struct heca_memory_region *hmr_cache;
        seqlock_t hmr_seq_lock;

        struct rb_root push_cache;
        seqlock_t push_cache_lock;

        struct kobject hproc_kobject;

        struct llist_head heca_delayed_faults;
        struct delayed_work heca_delayed_gup_work;

        struct llist_head heca_deferred_gups;
        struct work_struct heca_deferred_gup_work;

        atomic_t refs;
};

#define for_each_valid_svm(svms, i)         \
        for (i = 0; i < (svms).num; i++)        \
if (likely((svms).ids[i]))

struct work_request_ele {
        struct heca_connection_element *ele;
        struct ib_send_wr wr;
        struct ib_sge sg;
        struct ib_send_wr *bad_wr;
        struct map_dma dsm_dma;
};

struct msg_work_request {
        struct work_request_ele *wr_ele;
        struct heca_page_pool_element *dst_addr;
        struct dsm_page_cache *dpc;
};

struct recv_work_req_ele {
        struct heca_connection_element *ele;
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
        pte_t pte;
        struct mm_struct *mm;
        unsigned long addr;

};

struct tx_callback {
        int (*func)(struct tx_buf_ele *);
};

struct tx_buf_ele {
        int id;
        struct heca_message *dsm_buf;
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
        struct heca_message *dsm_buf;
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
        struct heca_page_pool_element *ppe;
        uint64_t addr;
        int (*func)(struct tx_buf_ele *);
        struct heca_message dsm_buf;
        struct dsm_page_cache *dpc;
        int response;
        int need_ppe;

        struct llist_node lnode;
        struct list_head ordered_list;
};

struct deferred_gup {
        struct heca_message dsm_buf;
        struct heca_process *remote_svm;
        struct heca_connection_element *origin_ele;
        struct heca_memory_region *mr;
        struct llist_node lnode;
};


struct dsm_module_state {
        struct heca_connections_manager *rcm;
        struct mutex dsm_state_mutex;
        spinlock_t radix_lock;
        struct radix_tree_root dsm_tree_root;
        struct radix_tree_root mm_tree_root;
        struct list_head dsm_list;

        struct heca_space_kobjects dsm_kobjects;
        struct workqueue_struct * dsm_rx_wq;
        struct workqueue_struct * dsm_tx_wq;
};

struct svm_list {
        u32 dsm_id;
        u32 *ids;
        int num;
};

struct dsm_page_cache {
        struct heca_process *svm;
        unsigned long addr;
        u32 tag; /* used to diff between pull ops, and to store dsc for push ops */

        struct page *pages[MAX_SVMS_PER_PAGE];
        struct svm_list svms;
        /* memory barrier are ok with these atomic */
        atomic_t found;
        atomic_t nproc;
        int released;
        unsigned long bitmap;
        u32 redirect_svm_id;

        struct rb_node rb_node;
};

struct dsm_delayed_fault {
        unsigned long addr;
        struct llist_node node;
};

struct dsm_pte_data {
        struct vm_area_struct *vma;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
};

#define DSM_INFLIGHT            0x04
#define DSM_INFLIGHT_BITPOS     0x02
#define DSM_PUSHING             0x08
#define DSM_PUSHING_BITPOS      0x03

struct dsm_swp_data {
        struct heca_space *dsm;
        struct svm_list svms;
        u32 flags;
};

struct dsm_page_reader {
        u32 svm_id;
        struct dsm_page_reader *next;
};

void dsm_init_descriptors(void);
void dsm_destroy_descriptors(void);
u32 dsm_get_descriptor(u32, u32 *);
inline pte_t dsm_descriptor_to_pte(u32, u32);
inline struct svm_list dsm_descriptor_to_svms(u32);
void remove_svm_from_descriptors(struct heca_process *);
int swp_entry_to_dsm_data(swp_entry_t, struct dsm_swp_data *);
int dsm_swp_entry_same(swp_entry_t, swp_entry_t);
void dsm_clear_swp_entry_flag(struct mm_struct *, unsigned long, pte_t, int);
void init_dsm_cache_kmem(void);
void destroy_dsm_cache_kmem(void);
struct dsm_page_cache *dsm_alloc_dpc(struct heca_process *,
                unsigned long, struct svm_list, int, int);
void dsm_dealloc_dpc(struct dsm_page_cache **);
struct dsm_page_cache *dsm_cache_get(struct heca_process *,
                unsigned long);
struct dsm_page_cache *dsm_cache_get_hold(struct heca_process *,
                unsigned long);
struct dsm_page_cache *dsm_cache_release(struct heca_process *,
                unsigned long);
void dsm_destroy_page_pool(struct heca_connection_element *);
int dsm_init_page_pool(struct heca_connection_element *);
struct heca_page_pool_element *dsm_fetch_ready_ppe(struct heca_connection_element *);
struct heca_page_pool_element *dsm_prepare_ppe(struct heca_connection_element *, struct page *);
void dsm_ppe_clear_release(struct heca_connection_element *, struct heca_page_pool_element **);
void init_dsm_reader_kmem(void);
u32 dsm_lookup_page_read(struct heca_process *, unsigned long);
u32 dsm_extract_page_read(struct heca_process *, unsigned long);
int dsm_flag_page_read(struct heca_process *, unsigned long, u32);
int dsm_cache_add(struct heca_process *, unsigned long, int, int,
                struct dsm_page_cache **);
struct dsm_page_reader *dsm_delete_readers(struct heca_process *,
                unsigned long);
struct dsm_page_reader *dsm_lookup_readers(struct heca_process *,
                unsigned long);
int dsm_add_reader(struct heca_process *, unsigned long, u32);
inline void dsm_free_page_reader(struct dsm_page_reader *);

#endif /* HECA_STRUCT_H_ */
