#include "ioctl.h"
#include "task.h"
#include "base.h"

static int get_task_struct_by_pid(pid_t pid, struct task_struct **tsk)
{
    int ret = 0;
    const struct cred *cred = current_cred(), *tcred;

    heca_printk(KERN_DEBUG "<enter>");

    rcu_read_lock();
    *tsk = find_task_by_vpid(pid);
    if (!*tsk) {
        heca_printk(KERN_ERR "can't find pid %d", pid);
        ret = -ESRCH;
        goto done;
    }

    tcred = __task_cred(*tsk);
    if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
            !uid_eq(cred->euid, tcred->uid) &&
            !uid_eq(cred->euid, tcred->suid)) {
        ret = -EACCES;
        goto done;
    }

    get_task_struct(*tsk);
done:
    rcu_read_unlock();
    heca_printk(KERN_DEBUG "<exit> %d", ret);
    return ret;
}

struct mm_struct *find_mm_by_pid(pid_t pid)
{
    struct task_struct *tsk;
    struct mm_struct *mm;

    if (get_task_struct_by_pid(pid, &tsk))
        return NULL;
    mm = tsk->mm;
    put_task_struct(tsk);
    return mm;
}

int heca_attach_task(struct task_struct *tsk)
{
    return 0;
}

int heca_detach_task(struct task_struct *tsk)
{
    int ret = 0;
    struct dsm *dsm;
    struct subvirtual_machine *svm;
    struct list_head *pos, *n, *it;

    list_for_each (pos, &get_dsm_module_state()->dsm_list) {
        dsm = list_entry(pos, struct dsm, dsm_ptr);
        list_for_each_safe (it, n, &dsm->svm_list) {
            svm = list_entry(it, struct subvirtual_machine, svm_ptr);
            if (tsk == find_task_by_vpid(svm->pid)) {
                heca_printk(KERN_DEBUG "removing SVM associated with pid %d",
                        svm->pid);
                remove_svm(dsm->dsm_id, svm->svm_id);
            }
        }
    }
    return ret;
}

