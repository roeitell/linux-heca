#ifndef _HECA_IOCTL_H
#define _HECA_IOCTL_H

void __heca_printk(unsigned int level, const char *path, int line,
        const char *func, const char *format, ...);
#define heca_printk(fmt, args...) \
    __heca_printk(0, __FILE__, __LINE__, __func__, fmt, ##args);

#endif /* _HECA_IOCTL_H */

