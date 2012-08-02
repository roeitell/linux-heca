#include <dsm/dsm_module.h>

#ifdef CONFIG_DSM_DEBUG
static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0 = disable)");
#endif

#ifdef CONFIG_DSM_VERBOSE_PRINTK
/* strip the leading path if the given path is absolute */
static const char *sanity_file_name(const char *path)
{
    if (*path == '/')
    return strrchr(path, '/') + 1;
    else
    return path;
}
#endif

void __dsm_printk(unsigned int level, const char *path, int line, const char *format,
        ...)
{
#if defined(CONFIG_DSM_DEBUG) || defined(CONFIG_DSM_VERBOSE_PRINTK)
    va_list args;
#ifdef CONFIG_DSM_VERBOSE_PRINTK
    struct va_format vaf;
    char verbose_fmt[] = KERN_DEFAULT "DSM %s:%d %pV";
#endif

#ifdef CONFIG_DSM_DEBUG
    if (debug < level)
    return;
#endif

    va_start(args, format);
#ifdef CONFIG_DSM_VERBOSE_PRINTK
    vaf.fmt = format;
    vaf.va = &args;
    if (format[0] == '<' && format[2] == '>') {
        memcpy(verbose_fmt, format, 3);
        vaf.fmt = format + 3;
    } else if (level)
    memcpy(verbose_fmt, KERN_DEBUG, 3);
    printk(verbose_fmt, sanity_file_name(path), line, &vaf);
#else
    vprintk(format, args);
#endif
    va_end(args);
#endif
}

EXPORT_SYMBOL(__dsm_printk);

