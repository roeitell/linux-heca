#ifndef _HECA_IOCTL_H
#define _HECA_IOCTL_H

/* print */
void __heca_printk(const char *, int, const char *, const char *, ...);
#define heca_printk(fmt, ...) \
        __heca_printk(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

/* module */
inline struct heca_module_state *get_heca_module_state(void);
struct heca_module_state *create_heca_module_state(void);
void destroy_heca_module_state(void);

#endif /* _HECA_IOCTL_H */

