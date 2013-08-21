#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/heca_hook.h>

#if defined(CONFIG_HECA) || defined(CONFIG_HECA_MODULE)

#include <linux/writeback.h>
EXPORT_SYMBOL(set_page_dirty_balance);

#include <linux/rmap.h>
EXPORT_SYMBOL(page_lock_anon_vma_read);
EXPORT_SYMBOL(page_remove_rmap);
EXPORT_SYMBOL(page_address_in_vma);
EXPORT_SYMBOL(page_unlock_anon_vma_read);
EXPORT_SYMBOL(page_add_new_anon_rmap);
EXPORT_SYMBOL(anon_vma_prepare);
EXPORT_SYMBOL(page_move_anon_rmap);
EXPORT_SYMBOL(do_page_add_anon_rmap);

#include <linux/ksm.h>
EXPORT_SYMBOL(ksm_might_need_to_copy);
EXPORT_SYMBOL(ksm_madvise);

#include <linux/mm.h>
EXPORT_SYMBOL(__pte_alloc);
EXPORT_SYMBOL(vm_normal_page);
EXPORT_SYMBOL(handle_mm_fault);
EXPORT_SYMBOL(anon_vma_interval_tree_iter_next);
EXPORT_SYMBOL(anon_vma_interval_tree_iter_first);

#include <linux/huge_mm.h>
EXPORT_SYMBOL(split_huge_page);
EXPORT_SYMBOL(split_huge_page_to_list);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
EXPORT_SYMBOL(__split_huge_page_pmd);
#endif

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
EXPORT_SYMBOL(find_task_by_pid_ns);

#include "internal.h"
EXPORT_SYMBOL(munlock_vma_page);

static const struct heca_hook_struct *heca_hook;
static atomic_t refcount = ATOMIC_INIT(0);

const struct heca_hook_struct *heca_hook_read(void)
{
        const struct heca_hook_struct *hook = NULL;
        unsigned long found;

        /* don't toy with refcount if unregister initiated */
        smp_mb();
        if (!heca_hook)
                return NULL;

retry:
        found = atomic_read(&refcount);
        if (found > 0) {
                if (atomic_cmpxchg(&refcount, found, found+1) != found)
                        goto retry;

                /*
                 * again, back away if unregister initiated. smp_mb implied in
                 * atomic_cmpxchg.
                 */
                hook = heca_hook;
                if (unlikely(!hook))
                        atomic_dec(&refcount);
        }

        return hook;
}
EXPORT_SYMBOL(heca_hook_read);

void heca_hook_release(const struct heca_hook_struct *hook)
{
        if (hook)
                atomic_dec(&refcount);
}
EXPORT_SYMBOL(heca_hook_release);

int heca_hook_register(const struct heca_hook_struct *hook)
{
        if (!atomic_cmpxchg(&refcount, 0, -1)) {
                heca_hook = hook;
                atomic_add(2, &refcount);
                return 0;
        }

        return -EFAULT;
}
EXPORT_SYMBOL(heca_hook_register);

int heca_hook_unregister(void)
{
        int ret = 0;

        heca_hook = NULL;
        might_sleep();

        /* block until we release the hook */
        for (;;) {
                int found = atomic_cmpxchg(&refcount, 1, 0);

                switch (found) {
                case 1:
                        heca_hook = NULL;
                        goto out;
                case 0:
                        ret = -EFAULT;
                        goto out;
                default:
                        cond_resched();
                }
        }

out:
        return ret;
}
EXPORT_SYMBOL(heca_hook_unregister);


#else
const struct heca_hook_struct *heca_hook_read(void)
{
    return NULL;
}

void heca_hook_release(void)
{
}

int heca_hook_register(const struct heca_hook_struct *hook)
{
}

int heca_hook_unregister(void)
{
}
#endif


