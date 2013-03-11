#ifndef _HECA_TASK_H
#define _HECA_TASK_H

#include <linux/mm_types.h>
#include <linux/sched.h>

struct mm_struct *find_mm_by_pid(pid_t pid);
int heca_attach_task(struct task_struct *tsk);
int heca_detach_task(struct task_struct *tsk);

#endif /* _HECA_TASK_H */

