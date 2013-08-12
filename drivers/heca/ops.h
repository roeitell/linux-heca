#ifndef _HECA_OPS_H
#define _HECA_OPS_H

void init_kmem_deferred_gup_cache(void);
void destroy_kmem_deferred_gup_cache(void);
int dsm_claim_page(struct subvirtual_machine *, struct subvirtual_machine *,
                struct memory_region *, unsigned long, struct page *, int);
int request_dsm_page(struct page *, struct subvirtual_machine *,
                struct subvirtual_machine *, struct memory_region *,
                unsigned long, int (*)(struct tx_buf_ele *), int,
                struct dsm_page_cache *, struct heca_page_pool_element *);
int process_pull_request(struct heca_connection_element *, struct rx_buf_ele *);
int process_svm_status(struct heca_connection_element *, struct rx_buf_ele *);
int process_page_redirect(struct heca_connection_element *, struct tx_buf_ele *, u32);
int process_page_response(struct heca_connection_element *, struct tx_buf_ele *);
int process_page_claim(struct heca_connection_element *, struct dsm_message *);
int process_claim_ack(struct heca_connection_element *, struct tx_buf_ele *,
                struct dsm_message *);
void deferred_gup_work_fn(struct work_struct *);
int process_page_request_msg(struct heca_connection_element *, struct dsm_message *);
int dsm_request_page_pull(struct heca_space *, struct subvirtual_machine *,
                struct page *, unsigned long, struct mm_struct *,
                struct memory_region *);
int ack_msg(struct heca_connection_element *, struct dsm_message *, u32);
int unmap_range(struct heca_space *, int, pid_t, unsigned long, unsigned long);
int dsm_process_request_query(struct heca_connection_element *, struct rx_buf_ele *);
int dsm_process_query_info(struct tx_buf_ele *);

#endif /* _HECA_OPS_H */
