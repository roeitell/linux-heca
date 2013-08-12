#ifndef _HECA_IOCTL_H
#define _HECA_IOCTL_H

/* print */
void __heca_printk(const char *, int, const char *, const char *, ...);
#define heca_printk(fmt, ...) \
        __heca_printk(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

/* module */
inline struct dsm_module_state *get_dsm_module_state(void);
struct dsm_module_state *create_dsm_module_state(void);
void destroy_dsm_module_state(void);

#endif /* _HECA_IOCTL_H */

