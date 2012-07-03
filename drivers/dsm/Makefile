CFLAGS_dsm_page_fault.o := -I../../../include/dsm

dsm_rdma-y := dsm_sysfs.o dsm_ctl.o dsm_op.o dsm_handlers.o dsm_sr.o \
    dsm_search.o dsm_cache.o dsm_page_fault.o \
    dsm_page_request.o dsm_unmap.o dsm_utils.o

obj-$(CONFIG_DSM) += dsm_rdma.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
