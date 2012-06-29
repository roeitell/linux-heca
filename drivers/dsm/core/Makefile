CFLAGS_dsm_page_fault.o := -I../../../include/dsm/dsm_trace.h

obj-$(CONFIG_DSM_CORE) += dsm_search.o dsm_cache.o dsm_page_fault.o \
    dsm_page_request.o dsm_unmap.o dsm_utils.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
