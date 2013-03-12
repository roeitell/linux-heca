#ifndef _HECA_IOCTL_H
#define _HECA_IOCTL_H

/* print */
void __heca_printk(unsigned int level, const char *path, int line,
        const char *func, const char *format, ...);
#define heca_printk(fmt, args...) \
    __heca_printk(0, __FILE__, __LINE__, __func__, fmt, ##args);

/* module */
inline struct dsm_module_state *get_dsm_module_state(void);
struct dsm_module_state *create_dsm_module_state(void);
void destroy_dsm_module_state(void);

#endif /* _HECA_IOCTL_H */

