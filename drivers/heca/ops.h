#ifndef _HECA_OPS_H
#define _HECA_OPS_H

void init_kmem_deferred_gup_cache(void);
void destroy_kmem_deferred_gup_cache(void);
int dsm_claim_page(struct subvirtual_machine *, struct subvirtual_machine *,
        struct memory_region *, unsigned long);
int request_dsm_page(struct page *, struct subvirtual_machine *,
        struct subvirtual_machine *, struct memory_region *,
        unsigned long, int (*)(struct tx_buf_ele *), int,
        struct dsm_page_cache *, struct page_pool_ele *);
int process_pull_request(struct conn_element *, struct rx_buf_ele *);
int process_svm_status(struct conn_element *, struct rx_buf_ele *);
int process_page_redirect(struct conn_element *, struct tx_buf_ele *, u32);
int process_page_response(struct conn_element *, struct tx_buf_ele *);
int process_page_claim(struct conn_element *, struct dsm_message *);
void deferred_gup_work_fn(struct work_struct *);
int process_page_request_msg(struct conn_element *, struct dsm_message *);
int dsm_request_page_pull(struct dsm *, struct subvirtual_machine *,
        struct page *, unsigned long, struct mm_struct *,
        struct memory_region *);
int ack_msg(struct conn_element *, struct rx_buf_ele *);
int do_unmap_range(struct dsm *, int, void *, void *);

#endif /* _HECA_OPS_H */
