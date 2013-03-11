ccflags-y += -I${PWD}

heca-y := ioctl.o base.o conn.o ops.o pull.o push.o struct.o sysfs.o task.o

obj-$(CONFIG_HECA) += heca.o

modules clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@

