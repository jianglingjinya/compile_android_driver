# 用于编译进内核boot
#obj-$(CONFIG_LSDRIVER) += PAN.o

obj-m += PAN.o
PAN-y := lsdriver.o

# 注释这行为release编译，不会有pr_debug输出
#ccflags-y += -DDEBUG

ccflags-y += -O3

ccflags-y += -Wno-error

ccflags-y += -fno-stack-protector

ccflags-y += -fomit-frame-pointer

ccflags-y += -funroll-loops

ccflags-y += -std=gnu11 -Wno-declaration-after-statement

ccflags-y += -fstrict-aliasing

ccflags-y += -ffunction-sections -fdata-sections