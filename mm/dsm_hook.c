#include <linux/export.h>
#include <linux/dsm_hook.h>

const struct dsm_hook_struct *dsm_hook;
EXPORT_SYMBOL(dsm_hook);
#if defined(CONFIG_DSM) || defined(CONFIG_DSM_MODULE)
const struct dsm_hook_struct *dsm_hook_read(void)
{
    const struct dsm_hook_struct *hook;

    rcu_read_lock();
    hook = dsm_hook;
    rcu_read_unlock();
    return hook;
}
EXPORT_SYMBOL(dsm_hook_read);

void dsm_hook_write(const struct dsm_hook_struct *hook)
{
    rcu_assign_pointer(dsm_hook, hook);
    synchronize_rcu();
}
EXPORT_SYMBOL(dsm_hook_write);

#include <linux/writeback.h>
EXPORT_SYMBOL(set_page_dirty_balance);

#include <linux/rmap.h>
EXPORT_SYMBOL(page_lock_anon_vma);
EXPORT_SYMBOL(page_remove_rmap);
EXPORT_SYMBOL(page_address_in_vma);
EXPORT_SYMBOL(page_unlock_anon_vma);
EXPORT_SYMBOL(page_add_new_anon_rmap);
EXPORT_SYMBOL(anon_vma_prepare);
EXPORT_SYMBOL(page_move_anon_rmap);
EXPORT_SYMBOL(do_page_add_anon_rmap);

#include <linux/ksm.h>
EXPORT_SYMBOL(ksm_does_need_to_copy);
EXPORT_SYMBOL(ksm_madvise);

#include <linux/mm.h>
EXPORT_SYMBOL(__pte_alloc);
EXPORT_SYMBOL(vm_normal_page);
EXPORT_SYMBOL(handle_mm_fault);


#include <linux/gfp.h>
EXPORT_SYMBOL(alloc_pages_vma);

#include <linux/pagemap.h>
EXPORT_SYMBOL(linear_hugepage_index);
EXPORT_SYMBOL(__lock_page_or_retry);

#include <linux/swapops.h>
EXPORT_SYMBOL(migration_entry_wait);

#include <linux/memcontrol.h>
EXPORT_SYMBOL(mem_cgroup_uncharge_page);
EXPORT_SYMBOL(mem_cgroup_commit_charge_swapin);
EXPORT_SYMBOL(mem_cgroup_try_charge_swapin);
EXPORT_SYMBOL(mem_cgroup_cancel_charge_swapin);
EXPORT_SYMBOL(mem_cgroup_newpage_charge);

#include <linux/swap.h>
EXPORT_SYMBOL(rotate_reclaimable_page);
EXPORT_SYMBOL(lru_add_drain);
EXPORT_SYMBOL(try_to_free_swap);

#include <linux/mmu_notifier.h>
EXPORT_SYMBOL(__mmu_notifier_change_pte);
EXPORT_SYMBOL(__mmu_notifier_invalidate_page);

#include <asm-generic/pgtable.h>
EXPORT_SYMBOL(pmd_clear_bad);
EXPORT_SYMBOL(ptep_clear_flush);
EXPORT_SYMBOL(ptep_set_access_flags);

#include "internal.h"
EXPORT_SYMBOL(munlock_vma_page);

#else
const struct dsm_hook_struct *dsm_hook_read(void) {
    return NULL;
}
EXPORT_SYMBOL(dsm_hook_read);

void dsm_hook_write(const struct dsm_hook_struct *hook) {
}
EXPORT_SYMBOL(dsm_hook_write);
#endif

