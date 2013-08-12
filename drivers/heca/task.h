#ifndef _HECA_TASK_H
#define _HECA_TASK_H

#include <linux/mm_types.h>
#include <linux/sched.h>

pid_t get_current_pid(void);
struct mm_struct *find_mm_by_pid(pid_t );
int heca_attach_task(struct task_struct *);
int heca_detach_task(struct task_struct *);

#endif /* _HECA_TASK_H */

