#ifndef _HECA_PUSH_H
#define _HECA_PUSH_H

#define DSM_EXTRACT_SUCCESS     (1 << 0)
#define DSM_EXTRACT_REDIRECT    (1 << 1)
#define DSM_EXTRACT_FAIL        (1 << 2)

inline int dsm_is_congested(void);
inline void dsm_push_cache_release(struct heca_process *,
                struct dsm_page_cache **, int);
struct dsm_page_cache *dsm_push_cache_get_remove(struct heca_process *,
                unsigned long);
int dsm_extract_pte_data(struct dsm_pte_data *, struct mm_struct *,
                unsigned long);
int dsm_try_unmap_page(struct heca_process *, unsigned long,
                struct heca_process *, int);
int dsm_extract_page_from_remote(struct heca_process *,
                struct heca_process *, unsigned long, u16, pte_t *,
                struct page **, u32 *, int, struct heca_memory_region *);
struct page *dsm_find_normal_page(struct mm_struct *, unsigned long);
int dsm_prepare_page_for_push(struct heca_process *,
                struct svm_list, struct page *, unsigned long,
                struct mm_struct *, u32);
int dsm_cancel_page_push(struct heca_process *, unsigned long,
                struct page *);
int push_back_if_remote_dsm_page(struct page *);
int dsm_flag_page_remote(struct mm_struct *, struct heca_space *, u32, unsigned long);
u32 dsm_query_pte_info(struct heca_process *, unsigned long);
void dsm_invalidate_readers(struct heca_process *, unsigned long, u32);
int dsm_pte_present(struct mm_struct *, unsigned long);

#endif /* _HECA_PUSH_H */

