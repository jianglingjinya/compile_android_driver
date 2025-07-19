MODULE_NAME := PAN
RESMAN_CORE_OBJS:=entry.o
RESMAN_GLUE_OBJS:=
ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
else
	KDIR := /root/4.19.157/out
all:
	make -C $(KDIR) M=$(PWD) ARCH=arm64 CC=clang-19 LD=ld.lld SUBARCH=arm64 modules
	rm -rf *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
clean:
	rm -rf *.ko *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
endif
