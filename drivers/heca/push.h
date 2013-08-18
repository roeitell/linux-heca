#ifndef _HECA_PUSH_H
#define _HECA_PUSH_H

#define HECA_EXTRACT_SUCCESS     (1 << 0)
#define HECA_EXTRACT_REDIRECT    (1 << 1)
#define HECA_EXTRACT_FAIL        (1 << 2)

inline int heca_is_congested(void);
inline void heca_push_cache_release(struct heca_process *,
                struct heca_page_cache **, int);
struct heca_page_cache *heca_push_cache_get_remove(struct heca_process *,
                unsigned long);
int heca_extract_pte_data(struct heca_pte_data *, struct mm_struct *,
                unsigned long);
int heca_try_unmap_page(struct heca_process *, unsigned long,
                struct heca_process *, int);
int heca_extract_page_from_remote(struct heca_process *,
                struct heca_process *, unsigned long, u16, pte_t *,
                struct page **, u32 *, int, struct heca_memory_region *);
struct page *heca_find_normal_page(struct mm_struct *, unsigned long);
int heca_prepare_page_for_push(struct heca_process *,
                struct heca_process_list, struct page *, unsigned long,
                struct mm_struct *, u32);
int heca_cancel_page_push(struct heca_process *, unsigned long,
                struct page *);
int push_back_if_remote_heca_page(struct page *);
int hproc_flag_page_remote(struct mm_struct *, struct heca_space *, u32, unsigned long);
u32 heca_query_pte_info(struct heca_process *, unsigned long);
void heca_invalidate_readers(struct heca_process *, unsigned long, u32);
int heca_pte_present(struct mm_struct *, unsigned long);

#endif /* _HECA_PUSH_H */

