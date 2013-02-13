heca-y := dsm_base.o dsm.o dsm_conn.o dsm_ops.o dsm_pull.o dsm_push.o \
    dsm_struct.o dsm_sysfs.o

obj-$(CONFIG_DSM) += heca.o

modules clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@

