obj-$(CONFIG_SOFTIWARP) += siw.o

siw-objs :=  siw_main.o siw_cm.o siw_verbs.o siw_obj.o siw_qp.o siw_qp_tx.o siw_qp_rx.o siw_cq.o siw_cm.o siw_debug.o siw_ae.o siw_mem.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

