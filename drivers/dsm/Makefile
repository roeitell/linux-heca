obj-$(CONFIG_DSM) += dsm_rdma.o

dsm_rdma-objs := dsm_sysfs.o dsm_ctl.o  dsm_op.o dsm_handlers.o dsm_sr.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
