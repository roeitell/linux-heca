#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/heca_hook.h>

static const struct heca_hook_struct *heca_hook;
static atomic_t refcount = ATOMIC_INIT(0);

const struct heca_hook_struct *heca_hook_read(void)
{
    const struct heca_hook_struct *hook = NULL;
#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
    if (!ACCESS_ONCE(heca_hook))
        return NULL;
    if (atomic_inc_not_zero(&refcount)) {
        hook = ACCESS_ONCE(heca_hook);
        if (unlikely(!hook))
            atomic_dec(&refcount);
    }
#endif
    return hook;
}
EXPORT_SYMBOL(heca_hook_read);

void heca_hook_release(const struct heca_hook_struct *hook)
{
#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
    if (hook)
        atomic_dec(&refcount);
#endif
}
EXPORT_SYMBOL(heca_hook_release);

int heca_hook_register(const struct heca_hook_struct *hook)
{
#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
    if (!atomic_cmpxchg(&refcount, 0, -1)) {
        heca_hook = hook;
        atomic_add(2, &refcount);
        return 0;
    }
    return -EFAULT;
#endif
    return 0;
}
EXPORT_SYMBOL(heca_hook_register);

int heca_hook_unregister(void)
{
#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
    heca_hook = NULL;
    might_sleep();
    for (;;) {
        if (atomic_cmpxchg(&refcount, 1, 0) == 1) {
            heca_hook = NULL;
            return 0;
        }
        if (!atomic_read(&refcount))
            break;
        cond_resched();
    }
#endif
    return 0;
}
EXPORT_SYMBOL(heca_hook_unregister);

#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)
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

#include <linux/sched.h>
EXPORT_SYMBOL(find_task_by_vpid);

#include "internal.h"
EXPORT_SYMBOL(munlock_vma_page);

#else
const struct heca_hook_struct *heca_hook_read(void)
{
    return NULL;
}

void heca_hook_release(void)
{
}

void heca_hook_write(const struct heca_hook_struct *hook)
{
}
#endif


